package opcua

import (
	"context"
	"fmt"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
	"github.com/zmap/zgrab2"
)

type NodeDef struct {
	NodeID      *ua.NodeID         `json:"nodeID"`
	NodeClass   ua.NodeClass       `json:"nodeClass"`
	BrowseName  string             `json:"browseName"`
	Description string             `json:"description"`
	AccessLevel ua.AccessLevelType `json:"accessLevel"`
	Path        string             `json:"path"`
	DataType    string             `json:"dataType"`
	Writable    bool               `json:"writable"`
}

func (n *NodeDef) SetNodeClass(v *ua.DataValue) error {
	switch err := v.Status; err {
	case ua.StatusOK:
		n.NodeClass = ua.NodeClass(v.Value.Int())
		return nil
	default:
		return err
	}
}

func (n *NodeDef) SetBrowseName(v *ua.DataValue) error {
	switch err := v.Status; err {
	case ua.StatusOK:
		n.BrowseName = v.Value.String()
		return nil
	default:
		return err
	}
}

func (n *NodeDef) SetDescription(v *ua.DataValue) error {
	switch err := v.Status; err {
	case ua.StatusOK:
		if v.Value != nil {
			n.Description = v.Value.String()
		}
		return nil
	case ua.StatusBadAttributeIDInvalid:
		return nil
	default:
		return err
	}
}

func (n *NodeDef) SetAccessLevel(v *ua.DataValue) error {
	switch err := v.Status; err {
	case ua.StatusOK:
		n.AccessLevel = ua.AccessLevelType(v.Value.Int())
		n.Writable = n.AccessLevel&ua.AccessLevelTypeCurrentWrite == ua.AccessLevelTypeCurrentWrite
		return nil
	case ua.StatusBadAttributeIDInvalid:
		return nil
	default:
		return err
	}
}

func (n *NodeDef) SetDataType(dt *ua.DataValue) error {
	switch err := dt.Status; err {
	case ua.StatusOK:
		switch v := dt.Value.NodeID().IntID(); v {
		case id.DateTime:
			n.DataType = "time.Time"
		case id.Boolean:
			n.DataType = "bool"
		case id.SByte:
			n.DataType = "int8"
		case id.Int16:
			n.DataType = "int16"
		case id.Int32:
			n.DataType = "int32"
		case id.Byte:
			n.DataType = "byte"
		case id.UInt16:
			n.DataType = "uint16"
		case id.UInt32:
			n.DataType = "uint32"
		case id.UtcTime:
			n.DataType = "time.Time"
		case id.String:
			n.DataType = "string"
		case id.Float:
			n.DataType = "float32"
		case id.Double:
			n.DataType = "float64"
		default:
			n.DataType = dt.Value.NodeID().String()
		}
		return nil
	case ua.StatusBadAttributeIDInvalid:
		return nil
	default:
		return err
	}
}

type ApplicationResult struct {
	ApplicationDescription *ua.ApplicationDescription
	ApplicationURLS        []*ApplicationURL
}

type ApplicationURL struct {
	URL       string
	Endpoints []*EndpointResult `json:"endpoints,omitempty"`
}

func newApplicationURL(url string) *ApplicationURL {
	return &ApplicationURL{
		URL:       url,
		Endpoints: []*EndpointResult{},
	}
}

func (app *ApplicationURL) setEndpoints(eps []*ua.EndpointDescription) {
	for _, ep := range eps {
		r := newEndpoint(ep)
		app.Endpoints = append(app.Endpoints, r)
	}
}

func newApplication(app *ua.ApplicationDescription) *ApplicationResult {
	return &ApplicationResult{
		ApplicationURLS:        []*ApplicationURL{},
		ApplicationDescription: app,
	}
}

type EndpointResult struct {
	Error               *zgrab2.ScanError `json:"error,omitempty"`
	EndpointDescription *ua.EndpointDescription
	Authenticated       []string               `json:"authentication"`
	Endpoint            map[string]interface{} `json:"endpoint"`
	Nodes               []*NodeDef             `json:"nodes"`
	Namespaces          []string               `json:"namespaces"`
}

func newEndpoint(ep *ua.EndpointDescription) *EndpointResult {
	return &EndpointResult{
		EndpointDescription: ep,
		Authenticated:       []string{},
	}
}

type Results struct {
	Applications []*ApplicationResult `json:"applications"`
}

type browser struct {
	level    uint
	maxLevel uint
	ctx      context.Context
}

func newBrowser(level uint, ctx context.Context) *browser {
	b := &browser{
		ctx:      ctx,
		maxLevel: 10,
	}
	b.setLevel(level)

	return b
}

func (b *browser) setLevel(level uint) {
	if level > b.maxLevel {
		panic(fmt.Errorf("failed to set browser level. The maximum level is %d, but attempted to set %d", b.maxLevel, level))
	}
	b.level = level
}

func (b *browser) Node(n *opcua.Node) (*NodeDef, error) {
	var def = &NodeDef{
		NodeID: n.ID,
	}

	// NOTE: We do not need to know anything else about the node
	// If you are modifying this, please be aware of possible
	// ethical issues. Reading values from nodes will not offer
	// more insights.
	attrs, err := n.Attributes(
		b.ctx,
		ua.AttributeIDNodeClass,
		ua.AttributeIDBrowseName,
		ua.AttributeIDDescription,
		ua.AttributeIDAccessLevel,
		ua.AttributeIDDataType,
	)
	if err != nil {
		return def, err
	}

	for i, f := range []func(v *ua.DataValue) error{
		def.SetNodeClass,
		def.SetBrowseName,
		def.SetDescription,
		def.SetAccessLevel,
		def.SetDataType,
	} {
		if err := f(attrs[i]); err != nil {
			return def, err
		}
	}

	return def, nil
}

func (b *browser) getChildren(refType uint32, n *opcua.Node, path string, level int) ([]*NodeDef, error) {
	refs, err := n.ReferencedNodes(b.ctx, refType, ua.BrowseDirectionForward, ua.NodeClassAll, true)
	if err != nil {
		return nil, fmt.Errorf("failed to set reference %d: %w", refType, err)
	}

	var nodes []*NodeDef
	for _, rn := range refs {
		children, err := b.browse(rn, path, level+1)
		if err != nil {
			return nodes, fmt.Errorf("failed to browse children: %w", err)
		}
		nodes = append(nodes, children...)
	}
	return nodes, nil
}

func (b *browser) browse(n *opcua.Node, path string, level int) ([]*NodeDef, error) {
	if level > int(b.level) {
		return nil, nil
	}

	def, err := b.Node(n)
	if err != nil {
		return nil, err
	}
	def.Path = join(path, def.BrowseName)

	var nodes []*NodeDef
	nodes = append(nodes, def)
	for _, refType := range []uint32{id.HasComponent, id.Organizes, id.HasProperty} {
		nChilds, err := b.getChildren(refType, n, def.Path, level)
		if err != nil {
			return nodes, err
		}
		nodes = append(nodes, nChilds...)
	}
	return nodes, nil
}

func join(a, b string) string {
	if a == "" {
		return b
	}
	return a + "." + b
}
