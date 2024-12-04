package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"
)

type KeyInfo struct {
	Name    string
	Version string
}

type DetectorInfo struct {
	Name  string
	Vault string
	Keys  []KeyInfo
}

var detectorVersionContent = make(map[string]string)

func main() {

	if len(os.Args) < 4 {
		log.Fatalf("Usage: %s <directory_path> <gcp_project_name> <prefix>(optional)  ...]", os.Args[0])
	}

	fmt.Println("Starting ....")

	// detector directory path
	pkgDir := os.Args[1]
	projectId := os.Args[2]
	filePrefix := os.Args[3]

	testFilePaths, err := getIntegrationTestFilePaths(pkgDir, filePrefix)
	if err != nil {
		log.Fatalf("failed to get test file paths: %v", err)
	}

	detectorInfos, err := extractKeysFromFile(testFilePaths)
	if err != nil {
		log.Fatalf("failed to extract keys from file: %v", err)
	}

	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatalf("failed to create secretmanager client: %v", err)
	}
	defer client.Close()

	for _, detectorInfo := range detectorInfos {
		if len(detectorInfo.Keys) > 0 {
			err := findVaultVersion(ctx, client, projectId, &detectorInfo)
			if err != nil {
				log.Println(fmt.Sprintf("failed to find vault version: %v", err))
				continue
			}
			printDetectorInfo(detectorInfo)
		}
	}
}

func printDetectorInfo(detectorInfo DetectorInfo) {
	fmt.Println("---------------")
	fmt.Println("Detector Name: ", detectorInfo.Name)
	for _, key := range detectorInfo.Keys {
		if key.Version != "" {
			fmt.Println(fmt.Sprintf("%s: %s version %s\n", key.Name, detectorInfo.Vault, key.Version))
		} else {
			fmt.Println(fmt.Sprintf("%s: not found", key.Name))
		}
	}
	fmt.Println("---------------")
}

func getIntegrationTestFilePaths(pkgDir, filePrefix string) ([]string, error) {
	var testFilePaths []string
	err := filepath.Walk(pkgDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if filePrefix == "" || strings.HasPrefix(info.Name(), filePrefix) {
			if strings.HasSuffix(path, "_test.go") {
				testFilePaths = append(testFilePaths, path)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return testFilePaths, nil
}

func extractKeysFromFile(testFilePaths []string) ([]DetectorInfo, error) {

	var results []DetectorInfo
	for _, testFilePath := range testFilePaths {
		content, err := ioutil.ReadFile(testFilePath)
		if err != nil {
			return nil, err
		}

		var detectorInfo DetectorInfo

		// filter out _test.go or _integration_test.go from the file name
		detectorInfo.Name = strings.TrimSuffix(filepath.Base(testFilePath), "_test.go")
		detectorInfo.Name = strings.TrimSuffix(detectorInfo.Name, "_integration")

		vaultNameRE := regexp.MustCompile(`"(detectors[1-5])"`)
		vaultMatches := vaultNameRE.FindAllStringSubmatch(string(content), -1)

		if len(vaultMatches) == 1 && len(vaultMatches[0]) == 2 {
			detectorInfo.Vault = vaultMatches[0][1]
		}

		keyRE := regexp.MustCompile(`MustGetField\("([A-Za-z0-9_]+)"\)?`)
		keyMatches := keyRE.FindAllStringSubmatch(string(content), -1)

		for _, match := range keyMatches {
			if len(match) != 2 {
				continue
			}
			var keyInfo KeyInfo
			keyInfo.Name = match[1]
			detectorInfo.Keys = append(detectorInfo.Keys, keyInfo)
		}

		results = append(results, detectorInfo)
	}

	return results, nil
}

// version name
func getVersionNumber(name string) string {
	var versionNumber = ""
	if name != "" {
		versionParts := strings.Split(name, "/")
		versionNumber = versionParts[len(versionParts)-1]
	}
	return versionNumber
}

func getVersionContent(ctx context.Context, client *secretmanager.Client, name string) (string, error) {

	if content, exits := detectorVersionContent[name]; exits {
		return content, nil
	}

	// Access the secret version
	accessReq := &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	}
	result, err := client.AccessSecretVersion(ctx, accessReq)
	if err != nil {
		log.Printf("failed to access secret version: %v", err)
		return "", err
	}

	detectorVersionContent[name] = string(result.Payload.Data)

	return detectorVersionContent[name], nil
}

func findVaultVersion(ctx context.Context, client *secretmanager.Client, projectId string, detectorInfo *DetectorInfo) error {

	if detectorInfo.Vault == "" {
		return errors.New("vault name is empty")
	}

	foundKeys := make([]string, 0, len(detectorInfo.Keys))

	// List all versions of the secret
	req := &secretmanagerpb.ListSecretVersionsRequest{
		Parent: fmt.Sprintf("projects/%s/secrets/%s", projectId, detectorInfo.Vault),
	}
	it := client.ListSecretVersions(ctx, req)

	for {
		version, err := it.Next()
		if err != nil {
			if errors.Is(err, iterator.Done) {
				return nil
			}

			return err
		}

		// if version state is non enabled, skip
		if version.State != secretmanagerpb.SecretVersion_ENABLED {
			continue
		}
		fmt.Println("Checking version: ", version.Name)

		// Check if the secret contains any of the keys
		secretData, err := getVersionContent(ctx, client, version.Name)
		if err != nil {
			return err
		}
		for i, key := range detectorInfo.Keys {
			if strings.Contains(secretData, key.Name) {
				detectorInfo.Keys[i].Version = getVersionNumber(version.Name)
				foundKeys = append(foundKeys, key.Name)
			}
		}

		if len(foundKeys) == len(detectorInfo.Keys) {
			break
		}
	}

	return nil
}
