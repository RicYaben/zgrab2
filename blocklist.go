package zgrab2

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

// RadixNode represents a node in the binary radix tree
type RadixNode struct {
	left, right *RadixNode
	isLeaf      bool
}

// RadixTree represents the tree
type RadixTree struct {
	root *RadixNode
}

// NewRadixTree creates an empty radix tree
func NewRadixTree() *RadixTree {
	return &RadixTree{root: &RadixNode{}}
}

// Insert adds a CIDR range to the radix tree
func (t *RadixTree) Insert(cidr *net.IPNet) {
	node := t.root
	bits := ipToBits(cidr.IP, cidr.Mask)

	for _, bit := range bits {
		if bit == 0 {
			if node.left == nil {
				node.left = &RadixNode{}
			}
			node = node.left
		} else {
			if node.right == nil {
				node.right = &RadixNode{}
			}
			node = node.right
		}
	}
	node.isLeaf = true
}

func (t *RadixTree) InsertEntry(entry string) error {
	// Parse the entry
	ip, cidr, err := net.ParseCIDR(entry)
	if err == nil {
		// Entry is a CIDR range
		t.Insert(cidr)
		return nil
	}

	// If not CIDR, treat it as a single IP
	ip = net.ParseIP(entry)
	if ip == nil {
		return fmt.Errorf("invalid IP or CIDR: %s", entry)
	}

	// Create a /32 or /128 mask for the single IP
	bits := net.IPv4len * 8 // Default to IPv4
	if ip.To4() == nil {
		bits = net.IPv6len * 8
	}
	mask := net.CIDRMask(bits, bits)
	cidr = &net.IPNet{IP: ip, Mask: mask}
	t.Insert(cidr)
	return nil
}

// Contains checks if an IP is covered by any CIDR range in the tree
func (t *RadixTree) Contains(ip net.IP) bool {
	node := t.root
	bits := ipToBits(ip, nil)

	for _, bit := range bits {
		if node.isLeaf {
			return true
		}
		if bit == 0 {
			if node.left == nil {
				return false
			}
			node = node.left
		} else {
			if node.right == nil {
				return false
			}
			node = node.right
		}
	}
	return node.isLeaf
}

// ipToBits converts an IP and optional mask to a binary slice
func ipToBits(ip net.IP, mask net.IPMask) []byte {
	ip = ip.To4() // Convert to IPv4
	bits := make([]byte, 0, len(ip)*8)
	for _, b := range ip {
		for i := 7; i >= 0; i-- {
			bits = append(bits, (b>>i)&1)
		}
	}

	if mask != nil {
		ones, _ := mask.Size()
		return bits[:ones]
	}
	return bits
}

func LoadBlocklist(source io.Reader) (*RadixTree, error) {
	tree := NewRadixTree()
	if source == nil {
		return tree, nil
	}

	scanner := bufio.NewScanner(source)
	for scanner.Scan() {
		txt := scanner.Text()
		if strings.HasPrefix(txt, "#") {
			continue
		}

		sp := strings.Split(txt, "#")
		txt = strings.TrimSpace(sp[0])
		if len(txt) == 0 {
			continue
		}

		if err := tree.InsertEntry(txt); err != nil {
			log.Printf("Invalid blocklist entry %s: %w", txt, err)
			continue
		}
	}
	if scanner.Err() != nil {
		return nil, scanner.Err()
	}

	return tree, nil
}
