package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"image"
	"image/jpeg"
	"image/png"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/ghodss/yaml"

	"github.com/automationbroker/bundle-lib/bundle"
	"github.com/coreos/go-semver/semver"
	"github.com/nfnt/resize"
	olmCSV "github.com/operator-framework/operator-lifecycle-manager/pkg/api/apis/clusterserviceversion/v1alpha1"
	olmRegistry "github.com/operator-framework/operator-lifecycle-manager/pkg/controller/registry"
	"github.com/spf13/cobra"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	apbOperatorImage = "docker.io/shurley/lostromos:canary"
	defaultAPBIcon   = "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"
)

var convertCmd = &cobra.Command{
	Use:   "convert",
	Short: "Convert apb.yml to operator resources",
	Long:  `Convert apb.yml to CustomResourceDefinition and ClusterServiceVersion for use as an operator`,
	Run: func(cmd *cobra.Command, args []string) {
		err := runConvert()
		if err != nil {
			panic(err) //TODO
		}
	},
}

var inputFile string
var outputDir string

func init() {
	convertCmd.Flags().StringVarP(&inputFile, "file", "f", "apb.yml", "path to APB spec")
	convertCmd.Flags().StringVarP(&outputDir, "output-dir", "o", "", "directory to store generated operator artifacts")
	rootCmd.AddCommand(convertCmd)
}

func runConvert() error {
	specBytes, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return err
	}
	var spec *bundle.Spec
	err = yaml.Unmarshal(specBytes, &spec)
	if err != nil {
		return err
	}
	csvs, crds, packages, err := convertSpec(spec)
	if err != nil {
		return err
	}
	return writeArtifacts(csvs, crds, packages)
}

func writeArtifacts(csvs []olmCSV.ClusterServiceVersion, crds []v1beta1.CustomResourceDefinition, packages []olmRegistry.PackageManifest) error {
	dirMode := os.FileMode(0766)
	fileMode := os.FileMode(0666)
	if outputDir == "" {
		outputDir = filepath.Join(filepath.Dir(inputFile), "operator-artifacts")
	}
	err := os.MkdirAll(outputDir, dirMode)
	if err != nil && !os.IsExist(err) {
		return err
	}

	for _, clusterServiceVersion := range csvs {
		err := os.Mkdir(filepath.Join(outputDir, "ClusterServiceVersions"), dirMode)
		if err != nil && !os.IsExist(err) {
			return err
		}
		path := filepath.Join(outputDir, "ClusterServiceVersions", clusterServiceVersion.Name+".yaml")
		dumped, err := yaml.Marshal(clusterServiceVersion)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(path, dumped, fileMode)
		if err != nil {
			return err
		}
	}
	for _, crd := range crds {
		err := os.Mkdir(filepath.Join(outputDir, "CustomResourceDefinitions"), dirMode)
		if err != nil && !os.IsExist(err) {
			return err
		}
		path := filepath.Join(outputDir, "CustomResourceDefinitions", crd.Name+".yaml")
		dumped, err := yaml.Marshal(crd)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(path, dumped, fileMode)
		if err != nil {
			return err
		}
	}
	for _, pkg := range packages {
		err := os.Mkdir(filepath.Join(outputDir, "Packages"), dirMode)
		if err != nil && !os.IsExist(err) {
			return err
		}
		path := filepath.Join(outputDir, "Packages", pkg.PackageName+".yaml")
		dumped, err := yaml.Marshal(pkg)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(path, dumped, fileMode)
		if err != nil {
			return err
		}
	}
	return nil
}

func convertSpec(spec *bundle.Spec) ([]olmCSV.ClusterServiceVersion, []v1beta1.CustomResourceDefinition, []olmRegistry.PackageManifest, error) {
	csvs := []olmCSV.ClusterServiceVersion{}
	crds := []v1beta1.CustomResourceDefinition{}
	packages := []olmRegistry.PackageManifest{}
	for _, plan := range spec.Plans {
		crd := PlanToCRD(spec, plan)
		crds = append(crds, crd)
		csv, err := PlanToCSV(plan, spec, crd)
		if err != nil {
			return nil, nil, nil, err
		}
		csvs = append(csvs, *csv)
		packages = append(packages, olmRegistry.PackageManifest{
			PackageName: csv.ObjectMeta.Name,
			Channels: []olmRegistry.PackageChannel{
				olmRegistry.PackageChannel{
					Name:           csv.Spec.Maturity,
					CurrentCSVName: csv.ObjectMeta.Name,
				},
			},
		})

	}
	return csvs, crds, packages, nil
}

func PlanToCRD(spec *bundle.Spec, plan bundle.Plan) v1beta1.CustomResourceDefinition {
	resourceName := strings.ToLower(fmt.Sprintf("%s-%s", spec.FQName, plan.Name))
	parts := strings.Split(resourceName, "-")
	for i, part := range parts {
		parts[i] = strings.Title(part)
	}
	kind := strings.Join(parts, "-")
	plural := resourceName + "s"
	group := "bundle.automationbroker.io"
	version := "v1"

	return v1beta1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apiextensions.k8s.io/v1beta1",
			Kind:       "CustomResourceDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s.%s", plural, group),
		},
		Spec: v1beta1.CustomResourceDefinitionSpec{
			Group:   group,
			Version: version,
			Names: v1beta1.CustomResourceDefinitionNames{
				Kind:     kind,
				Plural:   plural,
				Singular: resourceName,
			},
			Scope: v1beta1.NamespaceScoped,
			Validation: &v1beta1.CustomResourceValidation{
				OpenAPIV3Schema: PlanToJSONSchema(plan),
			},
		},
		Status: v1beta1.CustomResourceDefinitionStatus{},
	}
}

func PlanToJSONSchema(plan bundle.Plan) *v1beta1.JSONSchemaProps {
	props := v1beta1.JSONSchemaProps{
		Type:                 "object",
		Description:          plan.Description,
		AdditionalProperties: &v1beta1.JSONSchemaPropsOrBool{Allows: false},
		Properties:           parametersToJSONSchema(plan.Parameters),
		Required:             []string{},
	}
	for _, param := range plan.Parameters {
		if param.Required {
			props.Required = append(props.Required, param.Name)
		}
	}
	return &props
}

func parametersToJSONSchema(params []bundle.ParameterDescriptor) map[string]v1beta1.JSONSchemaProps {
	properties := make(map[string]v1beta1.JSONSchemaProps)

	for _, param := range params {
		k := param.Name

		t := getType(param.Type)

		tmpProps := v1beta1.JSONSchemaProps{
			Title:       param.Title,
			Description: param.Description,
			Type:        t,
		}
		setStringValidators(param, &tmpProps)
		// setNumberValidators(param, properties[k])
		// setEnum(param, properties[k])
		properties[k] = tmpProps
	}

	return properties
}

func setStringValidators(pd bundle.ParameterDescriptor, prop *v1beta1.JSONSchemaProps) {
	// maxlength
	if pd.DeprecatedMaxlength > 0 {
		tmp := int64(pd.MaxLength)
		prop.MaxLength = &tmp
	}

	// max_length overrides maxlength
	if pd.MaxLength > 0 {
		tmp := int64(pd.MaxLength)
		prop.MaxLength = &tmp
	}
	// min_length
	if pd.MinLength > 0 {
		tmp := int64(pd.MinLength)
		prop.MinLength = &tmp
	}

	// do not set the regexp if it does not compile
	if pd.Pattern != "" {
		prop.Pattern = pd.Pattern
	}
}

// getType transforms an apb parameter type to a JSON Schema type
func getType(paramType string) string {
	return "string"
}

func apbDeployment(spec *bundle.Spec, plan bundle.Plan, crd v1beta1.CustomResourceDefinition) (string, error) {
	apbDeploymentTmpl := `permissions:
- serviceAccountName: {{.name}}-operator
  rules:
  - apiGroups: ['*']
    attributeRestrictions: null
    resources: ['*']
    verbs: ['*']
  - apiGroups:
    - {{.crdGroup}}
    resources:
    - {{.crdName}}
    verbs: ['*']
deployments:
- name: {{.name}}-operator
  spec:
    replicas: 1
    selector:
      matchLabels:
        name: {{.name}}-operator-alm-owned
    template:
      metadata:
        name: {{.name}}-operator-alm-owned
        labels:
          name: {{.name}}-operator-alm-owned
          purpose: lostromos
      spec:
        serviceAccountName: {{.name}}-operator
        containers:
        - name: lostromos
          image: {{.image}}
          imagePullPolicy: Always
          env:
          - name: MY_POD_NAMESPACE
            valueFrom:
              fieldRef:
                fieldPath: metadata.namespace
          args:
          - start
          - "--debug"
          - "--crd-name"
          - "{{.crdName}}"
          - "--crd-group"
          - "{{.crdGroup}}"
          - "--bundle-sandbox-role"
          - "admin"
          - "--bundle-plan"
          - "{{.bundlePlan}}"
          - "--bundle-spec"
          - "{{.b64Spec}}"
          restartPolicy: OnFailure`
	b := &bytes.Buffer{}
	serializedSpec, _ := json.Marshal(spec)
	params := map[string]interface{}{
		"image":      apbOperatorImage,
		"name":       crd.Spec.Names.Singular,
		"crdName":    crd.Spec.Names.Plural,
		"crdGroup":   crd.Spec.Group,
		"bundlePlan": plan.Name,
		"b64Spec":    base64.StdEncoding.EncodeToString(serializedSpec),
	}
	template.Must(template.New("").Parse(apbDeploymentTmpl)).Execute(b, params)
	y, err := yaml.YAMLToJSON(b.Bytes())
	if err != nil {
		return "", err //TODO
	}
	return string(y), nil
}

func getVersion(apb_version string) *semver.Version {
	var specVersion *semver.Version
	specVersion, err := semver.NewVersion(apb_version)
	if err == nil {
		return specVersion
	}
	specVersion, err = semver.NewVersion(apb_version + ".0")
	if err == nil {
		return specVersion
	}
	return semver.New(apb_version + ".0.0") //TODO
}

func PlanToCSV(plan bundle.Plan, spec *bundle.Spec, crd v1beta1.CustomResourceDefinition) (*olmCSV.ClusterServiceVersion, error) {

	specVersion := getVersion(spec.Version)
	csvName := fmt.Sprintf("%s.%s", spec.FQName, plan.Name)
	displayName := fmt.Sprintf("%s: %s plan", getAPBMeta(spec.Metadata, "displayName", spec.FQName), plan.Name)
	description := getAPBMeta(spec.Metadata, "longDescription", spec.Description)
	deployment, err := apbDeployment(spec, plan, crd)
	if err != nil {
		return nil, err
	}

	return &olmCSV.ClusterServiceVersion{
		TypeMeta: metav1.TypeMeta{
			Kind:       olmCSV.ClusterServiceVersionKind,
			APIVersion: olmCSV.ClusterServiceVersionAPIVersion,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      csvName,
			Namespace: "placeholder",
			Annotations: map[string]string{
				"tectonic-visibility": "ocs", //TODO
				"alm-examples":        generateExample(crd),
			},
		},
		Spec: olmCSV.ClusterServiceVersionSpec{
			DisplayName: displayName,
			Description: description,
			Keywords:    spec.Tags,
			Maintainers: []olmCSV.Maintainer{}, //TODO
			Version:     *specVersion,
			Maturity:    "alpha",
			Provider: olmCSV.AppLink{
				Name: "Automation Broker",
				URL:  "automationbroker.io",
			},
			Links: getLinks(spec.Metadata),
			Icon:  []olmCSV.Icon{getIcon(spec)},
			InstallStrategy: olmCSV.NamedInstallStrategy{
				StrategyName:    "deployment",
				StrategySpecRaw: json.RawMessage(deployment),
			},
			CustomResourceDefinitions: olmCSV.CustomResourceDefinitions{
				Owned: []olmCSV.CRDDescription{CRDToCSVCRD(crd)},
			},
		},
	}, nil
}

func getLinks(metadata map[string]interface{}) []olmCSV.AppLink {
	links := []olmCSV.AppLink{}

	for k, v := range metadata {
		stringified := fmt.Sprintf("%v", v)
		_, err := url.ParseRequestURI(stringified)
		if err != nil {
			// assume this is not a link
			continue
		}
		links = append(links, olmCSV.AppLink{
			Name: camelToTitle(k),
			URL:  stringified,
		})
	}
	return links
}

func camelToTitle(s string) string {
	ret := []string{}
	for _, r := range s {
		if r == unicode.ToUpper(r) {
			ret = append(ret, " ")
		}
		ret = append(ret, string(r))
	}
	return strings.Title(strings.Join(ret, ""))
}

func getIcon(spec *bundle.Spec) olmCSV.Icon {
	defaultReturn := olmCSV.Icon{
		Data:      defaultAPBIcon,
		MediaType: "image/png",
	}
	imageURL := getAPBMeta(spec.Metadata, "imageUrl", "")
	response, err := http.Get(imageURL)
	if err != nil {
		return defaultReturn
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)
	contentType := http.DetectContentType(buf.Bytes())

	imageContent, _, err := image.Decode(buf)
	if err != nil {
		return defaultReturn
	}
	resizedImage := resize.Thumbnail(48, 48, imageContent, resize.Lanczos3)
	imageBuffer := new(bytes.Buffer)

	switch contentType {
	case "image/jpeg":
		err = jpeg.Encode(imageBuffer, resizedImage, nil)
		if err != nil {
			return defaultReturn
		}
	case "image/png":
		err = png.Encode(imageBuffer, resizedImage)
		if err != nil {
			return defaultReturn
		}
	default:
		return defaultReturn
	}

	content := imageBuffer.Bytes()

	return olmCSV.Icon{
		Data:      base64.StdEncoding.EncodeToString(content),
		MediaType: contentType,
	}
}

// TODO: needs to be plural
func CRDToCSVCRD(crd v1beta1.CustomResourceDefinition) olmCSV.CRDDescription {
	return olmCSV.CRDDescription{
		Name:            crd.ObjectMeta.Name,
		DisplayName:     crd.Spec.Names.Kind,
		Version:         crd.Spec.Version,
		Kind:            crd.Spec.Names.Kind,
		SpecDescriptors: JSONSchemasToSpecDescriptors(crd.Spec.Validation.OpenAPIV3Schema),
	}
}

func JSONSchemasToSpecDescriptors(schema *v1beta1.JSONSchemaProps) []olmCSV.SpecDescriptor {
	descriptors := []olmCSV.SpecDescriptor{}
	for name, param := range schema.Properties {
		descriptors = append(descriptors, olmCSV.SpecDescriptor{
			Path:        name,
			DisplayName: param.Title,
			Description: param.Description,
			// Value: param.Default, TODO
		})
	}
	return descriptors
}

func generateExample(crd v1beta1.CustomResourceDefinition) string {
	parameters := map[string]string{}
	for k, _ := range crd.Spec.Validation.OpenAPIV3Schema.Properties {
		parameters[k] = ""
	}
	definition := []map[string]interface{}{{
		"apiVersion": fmt.Sprintf("%s/%s", crd.Spec.Group, crd.Spec.Version),
		"kind":       crd.Spec.Names.Kind,
		"metadata": map[string]string{
			"name":      "example",
			"namespace": "placeholder",
		},
		"spec": parameters,
	}}

	ret, err := json.Marshal(definition)
	if err != nil {
		return ""
	}
	return string(ret)
}

func getAPBMeta(meta map[string]interface{}, key string, fallback string) string {
	switch meta[key] {
	case nil:
		return fallback
	default:
		return fmt.Sprintf("%s", meta[key])
	}
}
