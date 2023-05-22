package parser

import (
	"errors"
	"fmt"

	"github.com/onesbom/onesbom/pkg/reader"
	onesbom "github.com/onesbom/onesbom/pkg/sbom"
	"github.com/puerco/protobom/pkg/sbom"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func New() *Parser {
	return &Parser{}
}

type Parser struct{}

// Read parses a file and returns a protobom SBOM object
func (p *Parser) Read(path string) (*sbom.Document, error) {
	// Parse the SBOM
	sbom1 := reader.New()

	doc, err := sbom1.ParseFile(path)
	if err != nil {
		return nil, fmt.Errorf("parsing document: %w", err)
	}

	bom := &sbom.Document{
		Metadata:     &sbom.Metadata{},
		RootElements: []string{},
		Nodes:        []*sbom.Node{},
		Edges:        []*sbom.Edge{},
	}

	for _, f := range doc.Nodes.Files() {
		pbFile, err := p.protoFile(f)
		if err != nil {
			return nil, fmt.Errorf("converting file to protobuf: %w", err)
		}
		bom.Nodes = append(bom.Nodes, pbFile)
	}

	for _, pkg := range doc.Nodes.Packages() {
		pbPackage, err := p.protoPackage(pkg)
		if err != nil {
			return nil, fmt.Errorf("converting package to protobuf: %w", err)
		}
		bom.Nodes = append(bom.Nodes, pbPackage)
	}

	for _, r := range doc.Relationships {
		pbRel, err := p.protoEdge(r)
		if err != nil {
			return nil, fmt.Errorf("converting relationship to protobuf: %w", err)
		}
		bom.Edges = append(bom.Edges, pbRel)
	}

	return bom, nil
}

// protoPackage converts a onesbom package into a protobom Node
func (p *Parser) protoPackage(pkg *onesbom.Package) (*sbom.Node, error) {
	if pkg == nil {
		return nil, errors.New("package is nil")
	}
	pbPackage := &sbom.Node{
		Id:               pkg.ID(),
		Type:             0,
		Name:             pkg.Name,
		Version:          pkg.Version,
		FileName:         pkg.FileName,
		UrlHome:          pkg.URL,
		UrlDownload:      pkg.DownloadLocation,
		Licenses:         []string{},
		LicenseConcluded: string(pkg.LicenseConcluded),
		LicenseComments:  pkg.LicenseComments,
		Copyright:        pkg.Copyright,
		Hashes:           pkg.Hashes,
		SourceInfo:       pkg.SourceInfo,
		PrimaryPurpose:   pkg.PrimaryPurpose,
		Comment:          pkg.Comment,
		Summary:          pkg.Summary,
		Description:      pkg.Description,
		//Suppliers:          []*sbom.Person{},
		//Originators:        []*sbom.Person{},
		ExternalReferences: []*sbom.ExternalReference{},
		Identifiers:        []*sbom.Identifier{},
		FileTypes:          []string{},
	}

	if pkg.ReleaseDate != nil {
		pbPackage.ReleaseDate = timestamppb.New(*pkg.ReleaseDate)
	}
	if pkg.BuiltDate != nil {
		pbPackage.BuildDate = timestamppb.New(*pkg.BuiltDate)
	}

	if pkg.ValidUntilDate != nil {
		pbPackage.ValidUntilDate = timestamppb.New(*pkg.ValidUntilDate)
	}

	if pkg.Attribution != nil {
		pbPackage.Attribution = *pkg.Attribution
	}

	for _, id := range pkg.Identifiers {
		pbPackage.Identifiers = append(pbPackage.Identifiers, &sbom.Identifier{
			Type:  id.Type,
			Value: id.Value,
		})
	}
	return pbPackage, nil
}

// protoFile takes a onesbom file and converts it to a protobom Node
func (p *Parser) protoFile(f *onesbom.File) (*sbom.Node, error) {
	if f == nil {
		return nil, errors.New("file is nil")
	}
	pbFile := &sbom.Node{
		Id:              f.ID(),
		Type:            1, // Always file
		Name:            f.Name,
		Licenses:        []string{},
		LicenseComments: f.LicenseComments,
		Copyright:       f.Copyright,
		Hashes:          f.Hashes,
		Comment:         f.Comment,
		FileTypes:       f.Types,
	}

	for _, l := range f.Licenses {
		pbFile.Licenses = append(pbFile.Licenses, string(l))
	}

	return pbFile, nil
}

// protoEdge converts a onebom relationship to a protbom Edge
func (p *Parser) protoEdge(r onesbom.Relationship) (*sbom.Edge, error) {
	if r.Source.ID() == "" {
		return nil, errors.New("source element does not have an ID")
	}
	if len(*r.Target) == 0 {
		return nil, errors.New("relationship has no target elements")
	}
	edge := &sbom.Edge{
		Type: string(r.Type),
		From: r.Source.ID(),
		To:   []string{},
	}

	for i, node := range *r.Target {
		if node.ID() == "" {
			return nil, fmt.Errorf("target node #%d has no ID", i)
		}
		edge.To = append(edge.To, node.ID())
	}

	return edge, nil
}
