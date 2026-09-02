// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux || darwin || windows) && !ts_omit_ssh

package tailcat

import (
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	ssh "github.com/tailscale/gliderssh"
)

// sftpServer is the part of sftp.Server and sftp.RequestServer the
// subsystem handler drives.
type sftpServer interface {
	Serve() error
	Close() error
}

// sftpSubsystemHandler returns the handler for the SSH "sftp"
// subsystem implied by opts, or nil if none should be registered.
func (s *Server) sftpSubsystemHandler(opts SSHOptions) ssh.SubsystemHandler {
	if opts.Files == nil && !opts.Shell {
		return nil
	}
	return func(sess ssh.Session) {
		var srv sftpServer
		if opts.Files != nil {
			rsrv, root, err := newRootedSFTPServer(sess, opts.Files)
			if err != nil {
				s.sshLogf("sftp session: %v", err)
				sess.Exit(1)
				return
			}
			defer root.Close()
			srv = rsrv
		} else {
			fsrv, err := newFullSFTPServer(sess)
			if err != nil {
				s.sshLogf("sftp session: %v", err)
				sess.Exit(1)
				return
			}
			srv = fsrv
		}
		err := srv.Serve()
		if errors.Is(err, io.EOF) {
			err = nil
		}
		// Exit must come before Close: Close closes the session
		// channel, and an exit-status sent after that is lost, making
		// scp report failure for successful transfers. Close still
		// runs afterwards to release any handles a client left open.
		if err != nil {
			s.sshLogf("sftp session: %v", err)
			sess.Exit(1)
		} else {
			sess.Exit(0)
		}
		srv.Close()
	}
}

// newFullSFTPServer returns an SFTP server for rwc with the same
// filesystem access a shell session has, for servers whose SSH
// already grants a shell. Relative paths resolve against the user's
// home directory, matching OpenSSH's sftp-server.
func newFullSFTPServer(rwc io.ReadWriteCloser) (*sftp.Server, error) {
	var opts []sftp.ServerOption
	if home, err := os.UserHomeDir(); err == nil {
		opts = append(opts, sftp.WithServerWorkingDirectory(home))
	}
	return sftp.NewServer(rwc, opts...)
}

// newRootedSFTPServer returns an SFTP server for rwc confined to
// fsrv.Dir with fsrv.Mode access, along with the os.Root confining
// it, which the caller must close after serving.
func newRootedSFTPServer(rwc io.ReadWriteCloser, fsrv *FileService) (*sftp.RequestServer, *os.Root, error) {
	root, err := os.OpenRoot(fsrv.Dir)
	if err != nil {
		return nil, nil, err
	}
	h := &rootedFiles{root: root, mode: fsrv.Mode}
	srv := sftp.NewRequestServer(rwc, sftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileList: h,
	})
	return srv, root, nil
}

// rootedFiles implements the pkg/sftp request handlers on top of an
// os.Root, enforcing a FileServeMode. One instance serves one SFTP
// session (one client connection).
type rootedFiles struct {
	root *os.Root
	mode FileServeMode

	mu    sync.Mutex
	wrote map[string]bool // rooted paths this session created or wrote, for FileServeWO stats
}

// rel converts a cleaned absolute SFTP request path ("/foo/bar") to
// an os.Root-relative one ("foo/bar", or "." for the root itself).
func rel(requestPath string) string {
	p := strings.TrimPrefix(path.Clean(requestPath), "/")
	if p == "" {
		return "."
	}
	return p
}

// markOwn records that this session wrote or created the rooted path
// p, allowing later stats of it in write-only mode.
func (h *rootedFiles) markOwn(p string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.wrote == nil {
		h.wrote = make(map[string]bool)
	}
	h.wrote[p] = true
}

// isOwn reports whether this session wrote or created the rooted
// path p.
func (h *rootedFiles) isOwn(p string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.wrote[p]
}

// Fileread implements [sftp.FileReader] (the SFTP Get method).
func (h *rootedFiles) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	if h.mode == FileServeWO {
		return nil, sftp.ErrSSHFxPermissionDenied
	}
	return h.root.Open(rel(r.Filepath))
}

// Filewrite implements [sftp.FileWriter] (the SFTP Put and Open
// methods).
func (h *rootedFiles) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	if h.mode == FileServeRO {
		return nil, sftp.ErrSSHFxPermissionDenied
	}
	pflags := r.Pflags()
	if pflags.Read && h.mode == FileServeWO {
		return nil, sftp.ErrSSHFxPermissionDenied
	}
	flags := os.O_WRONLY
	if pflags.Read && pflags.Write {
		flags = os.O_RDWR
	}
	if pflags.Append {
		flags |= os.O_APPEND
	}
	if pflags.Creat {
		flags |= os.O_CREATE
	}
	if pflags.Trunc {
		flags |= os.O_TRUNC
	}
	if pflags.Excl {
		flags |= os.O_EXCL
	}
	p := rel(r.Filepath)
	f, err := h.root.OpenFile(p, flags, 0644)
	if err != nil {
		return nil, err
	}
	if h.mode == FileServeWO {
		h.markOwn(p)
	}
	return f, nil
}

// Filecmd implements [sftp.FileCmder] (the SFTP Setstat, Rename,
// Rmdir, Mkdir, Link, Symlink, and Remove methods).
func (h *rootedFiles) Filecmd(r *sftp.Request) error {
	p := rel(r.Filepath)
	switch h.mode {
	case FileServeRO:
		return sftp.ErrSSHFxPermissionDenied
	case FileServeWO:
		// A drop box accepts new files and directories and lets a
		// session adjust what it itself wrote (SFTP clients commonly
		// follow an upload with Setstat to fix up permissions or
		// times), but can't touch anything else.
		switch r.Method {
		case "Mkdir":
			if err := h.root.Mkdir(p, 0755); err != nil {
				return err
			}
			h.markOwn(p)
			return nil
		case "Setstat":
			if !h.isOwn(p) {
				return sftp.ErrSSHFxPermissionDenied
			}
			return h.setstat(r, p)
		}
		return sftp.ErrSSHFxPermissionDenied
	}
	switch r.Method {
	case "Setstat":
		return h.setstat(r, p)
	case "Rename":
		return h.root.Rename(p, rel(r.Target))
	case "Rmdir", "Remove":
		return h.root.Remove(p)
	case "Mkdir":
		return h.root.Mkdir(p, 0755)
	case "Link":
		// For Link and Symlink, Request.Filepath is the link target
		// and Request.Target is the new link's path.
		return h.root.Link(p, rel(r.Target))
	case "Symlink":
		return h.root.Symlink(p, rel(r.Target))
	}
	return sftp.ErrSSHFxOpUnsupported
}

// setstat applies the Setstat request r to the rooted path p.
func (h *rootedFiles) setstat(r *sftp.Request, p string) error {
	attrs := r.Attributes()
	flags := r.AttrFlags()
	// UidGid is deliberately ignored: the tunnel is identity-free, so
	// client uid/gid numbers are meaningless here.
	if flags.Permissions {
		if err := h.root.Chmod(p, os.FileMode(attrs.Mode).Perm()); err != nil {
			return err
		}
	}
	if flags.Acmodtime {
		atime := time.Unix(int64(attrs.Atime), 0)
		mtime := time.Unix(int64(attrs.Mtime), 0)
		if err := h.root.Chtimes(p, atime, mtime); err != nil {
			return err
		}
	}
	if flags.Size {
		f, err := h.root.OpenFile(p, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		err = f.Truncate(int64(attrs.Size))
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// Filelist implements [sftp.FileLister] (the SFTP List, Stat, and
// Readlink methods).
func (h *rootedFiles) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	p := rel(r.Filepath)
	if h.mode == FileServeWO {
		switch r.Method {
		case "List", "Readlink":
			return nil, sftp.ErrSSHFxPermissionDenied
		case "Stat":
			if p != "." && !h.isOwn(p) {
				fi, err := h.root.Stat(p)
				if err != nil || !fi.IsDir() {
					return nil, os.ErrNotExist
				}
			}
		}
	}
	switch r.Method {
	case "List":
		fis, err := h.root.ReadDir(p)
		if err != nil {
			return nil, err
		}
		return fileInfoListerAt(fis), nil
	case "Stat":
		fi, err := h.root.Stat(p)
		if err != nil {
			return nil, err
		}
		return fileInfoListerAt([]os.FileInfo{fi}), nil
	case "Readlink":
		target, err := h.root.Readlink(p)
		if err != nil {
			return nil, err
		}
		return nameListerAt([]string{target}), nil
	}
	return nil, sftp.ErrSSHFxOpUnsupported
}

type fileInfoListerAt []os.FileInfo

func (l fileInfoListerAt) ListAt(dst []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(dst, l[offset:])
	if n < len(dst) {
		return n, io.EOF
	}
	return n, nil
}

type nameListerAt []string

func (l nameListerAt) ListAt(dst []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := 0
	for i := offset; i < int64(len(l)) && n < len(dst); i++ {
		dst[n] = namedFileInfo(l[i])
		n++
	}
	if int(offset)+n >= len(l) {
		return n, io.EOF
	}
	return n, nil
}

type namedFileInfo string

func (fi namedFileInfo) Name() string       { return string(fi) }
func (namedFileInfo) Size() int64           { return 0 }
func (namedFileInfo) Mode() os.FileMode     { return 0 }
func (namedFileInfo) ModTime() time.Time    { return time.Time{} }
func (namedFileInfo) IsDir() bool            { return false }
func (namedFileInfo) Sys() any               { return nil }
