package parser

import (
	"errors"
	"fmt"

	"github.com/onesbom/onesbom/pkg/reader"
	"github.com/onesbom/onesbom/pkg/sbom"
	"github.com/puerco/protobom/pkg/protobom"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func New() *Parser {
	return &Parser{}
}

type Parser struct{}

// Read parses a file and returns a protobom SBOM object
func (p *Parser) Read(path string) (*protobom.SBOM, error) {
	// Parse the SBOM
	sbom1 := reader.New()

	doc, err := sbom1.ParseFile(path)
	if err != nil {
		return nil, fmt.Errorf("parsing document: %w", err)
	}

	bom := &protobom.SBOM{
		Id:       "",
		Metadata: []*protobom.Property{},
		Nodes:    []*protobom.Node{},
		Graph:    []*protobom.Edge{},
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
		pbRel, err := p.protoRelationship(r)
		if err != nil {
			return nil, fmt.Errorf("converting relationship to protobuf: %w", err)
		}
		bom.Graph = append(bom.Graph, pbRel)
	}

	return bom, nil
}

// protoPackage converts a onesbom package into a protobom Node
func (p *Parser) protoPackage(pkg *sbom.Package) (*protobom.Node, error) {
	if pkg == nil {
		return nil, errors.New("package is nil")
	}
	pbPackage := &protobom.Node{
		Id:   pkg.ID(),
		Type: 0,
		Metadata: []*protobom.Property{
			{Name: "name", Value: pkg.Name},
			{Name: "url", Value: pkg.URL},
			{Name: "comment", Value: pkg.Comment},
			{Name: "licenseComments", Value: pkg.LicenseComments},
			{Name: "copyright", Value: pkg.Copyright},
			{Name: "licenseConcluded", Value: string(pkg.LicenseConcluded)},
			{Name: "sourceInfo", Value: pkg.SourceInfo},
			{Name: "primaryPurpose", Value: pkg.PrimaryPurpose},
			{Name: "version", Value: pkg.Version},
			{Name: "fileName", Value: pkg.FileName},
			{Name: "summary", Value: pkg.Summary},
			{Name: "description", Value: pkg.Description},
			{Name: "downloadLocation", Value: pkg.DownloadLocation},
			{Name: "releaseDate", Time: timestamppb.New(*pkg.ReleaseDate)},
			{Name: "builtDate", Time: timestamppb.New(*pkg.BuiltDate)},
			{Name: "validUntilDate", Time: timestamppb.New(*pkg.ValidUntilDate)},
		},
	}

	attribProperty := &protobom.Property{Name: "attribution", Properties: []*protobom.Property{}}
	for i, a := range *pkg.Attribution {
		attribProperty.Properties = append(attribProperty.Properties, &protobom.Property{
			Name:  fmt.Sprintf("%d", i),
			Value: a,
		})
	}
	pbPackage.Metadata = append(pbPackage.Metadata, attribProperty)

	hashesProperty := &protobom.Property{Name: "hashes", Properties: []*protobom.Property{}}
	for algo, h := range pkg.Hashes {
		hashesProperty.Properties = append(hashesProperty.Properties, &protobom.Property{
			Name:  algo,
			Value: h,
		})
	}
	pbPackage.Metadata = append(pbPackage.Metadata, hashesProperty)

	identifierProperty := &protobom.Property{Name: "identifiers", Properties: []*protobom.Property{}}
	for _, id := range pkg.Identifiers {
		identifierProperty.Properties = append(identifierProperty.Properties, &protobom.Property{
			Name:  id.Type,
			Value: id.Value,
		})
	}
	pbPackage.Metadata = append(pbPackage.Metadata, identifierProperty)

	return pbPackage, nil
}

// protoFile takes a onesbom file and converts it to a protobom Node
func (p *Parser) protoFile(f *sbom.File) (*protobom.Node, error) {
	if f == nil {
		return nil, errors.New("file is nil")
	}
	pbFile := &protobom.Node{
		Id:   f.ID(),
		Type: 1,
		Metadata: []*protobom.Property{
			{Name: "name", Value: f.Name},
			{Name: "url", Value: f.URL},
			{Name: "comment", Value: f.Comment},
			{Name: "licenseComments", Value: f.LicenseComments},
			{Name: "copyright", Value: f.Copyright},
			{Name: "licenseConcluded", Value: string(f.LicenseConcluded)},
		},
	}

	hashesProperty := &protobom.Property{Name: "hashes", Properties: []*protobom.Property{}}
	for algo, h := range f.Hashes {
		hashesProperty.Properties = append(hashesProperty.Properties, &protobom.Property{
			Name:  algo,
			Value: h,
		})
	}
	pbFile.Metadata = append(pbFile.Metadata, hashesProperty)

	licenseProperty := &protobom.Property{
		Name:       "licenses",
		Properties: []*protobom.Property{},
	}

	for i, l := range f.Licenses {
		licenseProperty.Properties = append(licenseProperty.Properties, &protobom.Property{
			Name:  fmt.Sprintf("%d", i),
			Value: string(l),
		})
	}

	typesProperty := &protobom.Property{
		Name:       "types",
		Properties: []*protobom.Property{},
	}
	for i, t := range f.Types {
		typesProperty.Properties = append(typesProperty.Properties, &protobom.Property{
			Name:  fmt.Sprintf("%d", i),
			Value: t,
		})
	}

	return pbFile, nil
}

// protoRelationship converts a onebom relationship to a protbom Edge
func (p *Parser) protoRelationship(r sbom.Relationship) (*protobom.Edge, error) {
	if r.Source.ID() == "" {
		return nil, errors.New("source element does not have an ID")
	}
	if len(*r.Target) == 0 {
		return nil, errors.New("relationship has no target elements")
	}
	edge := &protobom.Edge{
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
