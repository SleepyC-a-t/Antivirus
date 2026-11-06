package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type VaultItem struct {
	ID       string    `json:"id"`
	Original string    `json:"original"`
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	SHA256   string    `json:"sha256"`
	Date     time.Time `json:"date"`
	Reason   string    `json:"reason"`
}

type Vault struct {
	path string
	mu   sync.Mutex
}

var validVaultID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func openVault() (*Vault, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		p, err := os.UserConfigDir()
		if err != nil {
			return nil, err
		}
		base = p
	}
	path := filepath.Join(base, "SentinelLite", "Quarantine")
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	return &Vault{path: path}, nil
}

func (v *Vault) data(id string) string { return filepath.Join(v.path, id+".quarantined") }
func (v *Vault) meta(id string) string { return filepath.Join(v.path, id+".json") }

func (v *Vault) list() ([]VaultItem, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.listLocked()
}
func (v *Vault) listLocked() ([]VaultItem, error) {
	es, err := os.ReadDir(v.path)
	if err != nil {
		return nil, err
	}
	out := []VaultItem{}
	for _, e := range es {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		if !validVaultID.MatchString(id) {
			continue
		}
		b, err := os.ReadFile(v.meta(id))
		if err != nil {
			continue
		}
		var it VaultItem
		if json.Unmarshal(b, &it) != nil || it.ID != id {
			continue
		}
		if st, err := os.Lstat(v.data(id)); err == nil && st.Mode().IsRegular() && !isReparse(v.data(id)) {
			out = append(out, it)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Date.After(out[j].Date) })
	return out, nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	h := sha256.New()
	if _, err = io.Copy(h, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copy to a newly created file; never follow a destination symlink or overwrite.
func copyNew(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	closeErr := out.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(dst)
	}
	return err
}

func safeMove(src, dst string) error {
	if _, err := os.Lstat(dst); err == nil {
		return errors.New("destination exists: refusing to overwrite")
	}
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	// os.Rename cannot move across different drive letters; copy, verify, then remove.
	tmp := dst + ".part"
	if err := copyNew(src, tmp); err != nil {
		return fmt.Errorf("move and copy both failed: %w", err)
	}
	originalHash, err := fileSHA256(src)
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	copiedHash, err := fileSHA256(tmp)
	if err != nil || originalHash != copiedHash {
		_ = os.Remove(tmp)
		return errors.New("copy verification failed; original was not removed")
	}
	if err = os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err = os.Remove(src); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("copy completed, but original could not be removed: %w", err)
	}
	return nil
}

func atomicJSON(path string, item VaultItem) error {
	b, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".part"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	cl := f.Close()
	if err == nil {
		err = cl
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

func (v *Vault) quarantine(f Finding) (VaultItem, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	p, err := filepath.Abs(f.Path)
	if err != nil {
		return VaultItem{}, err
	}
	if strings.HasPrefix(strings.ToLower(p), strings.ToLower(v.path)+string(os.PathSeparator)) {
		return VaultItem{}, errors.New("file is already in quarantine")
	}
	st, err := os.Lstat(p)
	if err != nil {
		return VaultItem{}, err
	}
	if !st.Mode().IsRegular() || isReparse(p) {
		return VaultItem{}, errors.New("file is a link or not a regular file")
	}
	if st.Size() != f.Size || !st.ModTime().Equal(f.Modified) {
		return VaultItem{}, errors.New("file has changed since scanning; scan it again")
	}
	id := newID()
	if st.Size() > 2*1024*1024*1024 {
		return VaultItem{}, errors.New("files above 2 GiB require manual handling; quarantine size limit")
	}
	item := VaultItem{ID: id, Original: p, Name: filepath.Base(p), Size: st.Size(), Date: time.Now(), Reason: strings.Join(f.Reasons, "; ")}
	// Save the checksum before moving so that the destination can be verified.
	item.SHA256, err = fileSHA256(p)
	if err != nil {
		return VaultItem{}, err
	}
	if f.ReviewSHA256 != "" && item.SHA256 != f.ReviewSHA256 {
		return VaultItem{}, errors.New("file content changed since the finding was reviewed; scan it again")
	}
	latest, err := os.Lstat(p)
	if err != nil || !os.SameFile(st, latest) || latest.Size() != st.Size() || !latest.ModTime().Equal(st.ModTime()) {
		return VaultItem{}, errors.New("file changed during verification")
	}
	if err = atomicJSON(v.meta(id), item); err != nil {
		return VaultItem{}, err
	}
	if err = safeMove(p, v.data(id)); err != nil {
		_ = os.Remove(v.meta(id))
		return VaultItem{}, err
	}
	verified, err := fileSHA256(v.data(id))
	if err != nil || verified != item.SHA256 {
		return item, errors.New("quarantine data integrity could not be verified; inspect vault before further changes")
	}
	return item, nil
}

func (v *Vault) getLocked(id string) (VaultItem, error) {
	if !validVaultID.MatchString(id) {
		return VaultItem{}, errors.New("invalid quarantine ID")
	}
	b, err := os.ReadFile(v.meta(id))
	if err != nil {
		return VaultItem{}, err
	}
	var item VaultItem
	if err = json.Unmarshal(b, &item); err != nil {
		return VaultItem{}, err
	}
	if item.ID != id {
		return VaultItem{}, errors.New("metadata does not match ID")
	}
	st, err := os.Lstat(v.data(id))
	if err != nil {
		return VaultItem{}, err
	}
	if !st.Mode().IsRegular() || isReparse(v.data(id)) {
		return VaultItem{}, errors.New("quarantine entry is not a regular file")
	}
	return item, nil
}

func (v *Vault) restore(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	it, err := v.getLocked(id)
	if err != nil {
		return err
	}
	hash, err := fileSHA256(v.data(id))
	if err != nil {
		return err
	}
	if hash != it.SHA256 {
		return errors.New("quarantined content has changed; restore refused")
	}
	if _, err = os.Lstat(it.Original); err == nil {
		return errors.New("original path already exists; refusing to overwrite")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err = os.Stat(filepath.Dir(it.Original)); err != nil {
		return fmt.Errorf("original folder is missing or inaccessible: %w", err)
	}
	if err = safeMove(v.data(id), it.Original); err != nil {
		return err
	}
	_ = os.Remove(v.meta(id))
	return nil
}
func (v *Vault) permanentlyDelete(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, err := v.getLocked(id); err != nil {
		return err
	}
	if err := os.Remove(v.data(id)); err != nil {
		return err
	}
	return os.Remove(v.meta(id))
}
