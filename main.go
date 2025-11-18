package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"
)

type ImageResult struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	Error  string            `json:"error,omitempty"`
}

type Output struct {
	Results []ImageResult `json:"results"`
	Summary Summary       `json:"summary"`
	Tag     string        `json:"tag,omitempty"`
	Checked int           `json:"checked"`
}

type Summary struct {
	WithLabels          int      `json:"with_labels"`
	WithoutLabels       int      `json:"without_labels"`
	Errors              int      `json:"errors"`
	ImagesWithLabels    []string `json:"images_with_labels,omitempty"`
	ImagesWithoutLabels []string `json:"images_without_labels,omitempty"`
	ImagesWithErrors    []string `json:"images_with_errors,omitempty"`
}

var (
	concurrency     int
	tag             string
	logLevel        string
	outputJSON      bool
	labelPrefix     string
	inputFile       string
	officialImages  bool
	useAuth         bool
)

var rootCmd = &cobra.Command{
	Use:   "check-oci-labels [flags] [image ...]",
	Short: "Check which container images have OCI labels set",
	Long: `Check which container images have OCI labels (or other labels) set.

Supports any registry - Docker Hub, GitHub Container Registry (ghcr.io),
Google Container Registry (gcr.io), Quay.io, and any OCI-compliant registry.

Images can be specified as arguments, read from a file, or piped via stdin.

Image format:
  - Official images: golang, python, node (assumes :latest tag)
  - With tags: golang:1.23, python:3.12-slim, node:20-alpine
  - Full references: synadia/nats-server:nightly
  - Other registries: ghcr.io/owner/repo:tag, gcr.io/project/image:v1.0

Note: If no tag is specified, :latest is assumed by default. Some images may
not have a :latest tag - specify an explicit tag for those images.

Log levels control structured logging output to stderr (as JSON):
  DEBUG - Show pull/inspect progress for each image
  WARN  - Show only warnings and errors
  ERROR - Show only errors`,
	Example: `  # Check Docker Hub official images (assumes :latest)
  check-oci-labels golang python node

  # Check with specific tags
  check-oci-labels golang:1.23 python:3.12-slim node:20-alpine

  # Check non-official Docker Hub images
  check-oci-labels synadia/nats-server:nightly traefik/traefik:v3.0

  # Check images from other registries
  check-oci-labels ghcr.io/owner/repo:tag gcr.io/project/image:v1.0

  # Check labels with custom prefix
  check-oci-labels --label-prefix "com.example." myapp

  # Check all labels (empty prefix)
  check-oci-labels --label-prefix "" nginx

  # List all Docker Official Images
  check-oci-labels --official-images

  # Read from file
  check-oci-labels --file images.txt

  # Pipe from stdin
  cat images.txt | check-oci-labels

  # JSON output
  check-oci-labels --json golang:1.23 python:3.12`,
	RunE: run,
}

func init() {
	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "j", runtime.NumCPU(), "Number of concurrent image pulls")
	rootCmd.Flags().StringVar(&tag, "tag", "latest", "Tag to check for each image (if not specified in image name)")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "INFO", "Log level (DEBUG, INFO, WARN, ERROR)")
	rootCmd.Flags().BoolVar(&outputJSON, "json", false, "Output results as JSON")
	rootCmd.Flags().StringVar(&labelPrefix, "label-prefix", "org.opencontainers.", "Label prefix to filter (use empty string \"\" for all labels)")
	rootCmd.Flags().StringVarP(&inputFile, "file", "f", "", "Read image list from file (one per line)")
	rootCmd.Flags().BoolVar(&officialImages, "official-images", false, "List all Docker Official Images and exit")
	rootCmd.Flags().BoolVar(&useAuth, "auth", false, "Use Docker credentials for authentication (avoids rate limits)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	// Parse log level using slog's built-in UnmarshalText
	var level slog.Level
	if err := level.UnmarshalText([]byte(logLevel)); err != nil {
		return fmt.Errorf("invalid log level: %s (must be DEBUG, INFO, WARN, or ERROR)", logLevel)
	}

	// Setup structured logging to stderr as JSON
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	// If --official-images, fetch and print official images
	if officialImages {
		images, err := fetchOfficialImages()
		if err != nil {
			return fmt.Errorf("failed to fetch official images: %w", err)
		}
		for _, img := range images {
			fmt.Println(img)
		}
		return nil
	}

	images := args

	// Read from file if specified
	if inputFile != "" {
		fileImages, err := readImagesFromFile(inputFile)
		if err != nil {
			return fmt.Errorf("failed to read images from file: %w", err)
		}
		images = append(images, fileImages...)
	}

	// Read from stdin if no images specified and not a TTY
	if len(images) == 0 && !isTerminal() {
		stdinImages, err := readImagesFromStdin()
		if err != nil {
			return fmt.Errorf("failed to read images from stdin: %w", err)
		}
		images = append(images, stdinImages...)
	}

	if len(images) == 0 {
		return fmt.Errorf("no images to check - provide images as arguments, via --file, or via stdin")
	}

	slog.Debug("Starting label check", "image_count", len(images), "tag", tag, "concurrency", concurrency)

	results := checkImages(images, tag, concurrency)

	if outputJSON {
		return printJSON(results, tag)
	}

	printResults(results)
	return nil
}

func readImagesFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var images []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") {
			images = append(images, line)
		}
	}

	return images, scanner.Err()
}

func readImagesFromStdin() ([]string, error) {
	var images []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") {
			images = append(images, line)
		}
	}

	return images, scanner.Err()
}

func isTerminal() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return true
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func checkImages(images []string, tag string, concurrency int) []ImageResult {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		slog.Error("Error creating Docker client", "error", err)
		os.Exit(1)
	}
	defer cli.Close()

	// Get auth config once - assume all images use same registry (Docker Hub by default)
	authStr := ""
	if useAuth {
		authConfig, err := getAuthConfig("docker.io")
		if err != nil {
			slog.Debug("Could not load auth config", "error", err)
		}

		// Encode auth config for Docker API
		if authConfig.Username != "" {
			authBytes, _ := json.Marshal(authConfig)
			authStr = base64.URLEncoding.EncodeToString(authBytes)
			slog.Debug("Using authentication")
		}
	} else {
		slog.Debug("Skipping authentication (no --auth flag)")
	}

	results := make([]ImageResult, len(images))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)

	for i, img := range images {
		wg.Add(1)
		go func(index int, imageName string) {
			defer wg.Done()

			semaphore <- struct{}{}        // Acquire
			defer func() { <-semaphore }() // Release

			results[index] = checkImage(ctx, cli, imageName, tag, authStr)
		}(i, img)
	}

	wg.Wait()
	return results
}

func checkImage(ctx context.Context, cli *client.Client, imageName, tag, authStr string) ImageResult {
	result := ImageResult{
		Name:   imageName,
		Labels: make(map[string]string),
	}

	// If image already has a tag or digest, don't append tag
	imageRef := imageName
	if !strings.Contains(imageName, ":") && !strings.Contains(imageName, "@") {
		imageRef = imageName + ":" + tag
	}

	slog.Debug("Pulling image", "image", imageRef)

	// Pull the image
	reader, err := cli.ImagePull(ctx, imageRef, image.PullOptions{
		RegistryAuth: authStr,
	})
	if err != nil {
		result.Error = err.Error()
		slog.Warn("Failed to pull image", "image", imageRef, "error", err)
		return result
	}
	// Drain the pull output
	_, _ = io.Copy(io.Discard, reader)
	reader.Close()

	// Inspect the image
	inspect, err := cli.ImageInspect(ctx, imageRef)
	if err != nil {
		result.Error = err.Error()
		slog.Warn("Failed to inspect image", "image", imageRef, "error", err)
		return result
	}

	// Extract labels based on prefix (empty prefix matches all)
	if inspect.Config != nil && inspect.Config.Labels != nil {
		for key, value := range inspect.Config.Labels {
			if labelPrefix == "" || strings.HasPrefix(key, labelPrefix) {
				result.Labels[key] = value
			}
		}
	}

	if len(result.Labels) > 0 {
		slog.Debug("Image has matching labels", "image", imageRef, "label_count", len(result.Labels))
	} else {
		slog.Debug("Image has no matching labels", "image", imageRef)
	}

	return result
}

func printJSON(results []ImageResult, tag string) error {
	var withLabels, withoutLabels, errors int
	var imagesWithLabels, imagesWithoutLabels, imagesWithErrors []string

	for _, result := range results {
		if result.Error != "" {
			errors++
			imagesWithErrors = append(imagesWithErrors, result.Name)
		} else if len(result.Labels) > 0 {
			withLabels++
			imagesWithLabels = append(imagesWithLabels, result.Name)
		} else {
			withoutLabels++
			imagesWithoutLabels = append(imagesWithoutLabels, result.Name)
		}
	}

	output := Output{
		Results: results,
		Checked: len(results),
		Summary: Summary{
			WithLabels:          withLabels,
			WithoutLabels:       withoutLabels,
			Errors:              errors,
			ImagesWithLabels:    imagesWithLabels,
			ImagesWithoutLabels: imagesWithoutLabels,
			ImagesWithErrors:    imagesWithErrors,
		},
	}

	// Only include tag if it was used
	if len(results) > 0 && (tag != "latest" || !strings.Contains(results[0].Name, ":")) {
		output.Tag = tag
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	total := withLabels + withoutLabels + errors
	slog.Debug("Check complete", "with_labels", withLabels, "without_labels", withoutLabels, "errors", errors, "total", total)

	return nil
}

func printResults(results []ImageResult) {
	var withLabels, withoutLabels, errors int

	for i, result := range results {
		if result.Error != "" {
			errors++
			fmt.Printf("[%d/%d] %s - ERROR: %v\n", i+1, len(results), result.Name, result.Error)
			continue
		}

		hasLabels := len(result.Labels) > 0
		if hasLabels {
			withLabels++
			fmt.Printf("[%d/%d] %s - HAS LABELS\n", i+1, len(results), result.Name)
			printLabels(result.Labels)
		} else {
			withoutLabels++
			fmt.Printf("[%d/%d] %s - no labels\n", i+1, len(results), result.Name)
		}
	}

	total := withLabels + withoutLabels + errors
	slog.Debug("Check complete", "with_labels", withLabels, "without_labels", withoutLabels, "errors", errors, "total", total)

	fmt.Println()
	fmt.Println("Summary:")
	fmt.Printf("  Images with labels:    %d\n", withLabels)
	fmt.Printf("  Images without labels: %d\n", withoutLabels)
	if errors > 0 {
		fmt.Printf("  Errors:                %d\n", errors)
	}
	fmt.Printf("  Total checked:         %d\n", total)
}

func printLabels(labels map[string]string) {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		fmt.Printf("  %s=%s\n", key, labels[key])
	}
	fmt.Println()
}

// getAuthConfig reads credentials from ~/.docker/config.json for the appropriate registry
func getAuthConfig(imageRef string) (registry.AuthConfig, error) {
	var authConfig registry.AuthConfig

	home, err := os.UserHomeDir()
	if err != nil {
		return authConfig, err
	}

	configPath := home + "/.docker/config.json"
	data, err := os.ReadFile(configPath)
	if err != nil {
		return authConfig, err
	}

	var config struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
		CredsStore string `json:"credsStore"`
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return authConfig, err
	}

	// Determine registry from image ref
	registryURL := getRegistryURL(imageRef)

	// If using credential store, try to get credentials from it
	if config.CredsStore != "" {
		slog.Debug("Using credential store", "store", config.CredsStore, "registry", registryURL)
		return getAuthFromCredStore(config.CredsStore, registryURL)
	}

	// Try to find auth directly in config file
	for registry, auth := range config.Auths {
		if strings.Contains(registry, registryURL) || (registryURL == "index.docker.io" && strings.Contains(registry, "docker.io")) {
			if auth.Auth != "" {
				// Decode base64 auth string
				decoded, err := base64.StdEncoding.DecodeString(auth.Auth)
				if err != nil {
					continue
				}
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) == 2 {
					authConfig.Username = parts[0]
					authConfig.Password = parts[1]
					slog.Debug("Loaded credentials from config", "username", authConfig.Username, "registry", registryURL)
					return authConfig, nil
				}
			}
		}
	}

	return authConfig, fmt.Errorf("no auth found for registry %s", registryURL)
}

// getRegistryURL extracts registry from image reference
func getRegistryURL(imageRef string) string {
	// Remove tag/digest if present
	parts := strings.Split(imageRef, "/")

	// If image starts with a domain (contains dot or port), use it as registry
	if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":")) {
		return parts[0]
	}

	// Default to Docker Hub
	return "index.docker.io"
}

// getAuthFromCredStore retrieves credentials from Docker credential helper
func getAuthFromCredStore(store string, registryURL string) (registry.AuthConfig, error) {
	var authConfig registry.AuthConfig

	// Try to execute docker-credential-<store> get
	cmd := fmt.Sprintf("docker-credential-%s", store)

	// Normalize registry URL for credential helper
	credRegistryURL := registryURL
	if registryURL == "index.docker.io" {
		credRegistryURL = "https://index.docker.io/v1/"
	} else if !strings.HasPrefix(registryURL, "http") {
		credRegistryURL = "https://" + registryURL
	}

	// Execute the credential helper
	proc := exec.Command(cmd, "get")
	proc.Stdin = strings.NewReader(credRegistryURL)
	output, err := proc.Output()
	if err != nil {
		return authConfig, fmt.Errorf("failed to get credentials from store %s: %w", store, err)
	}

	// Parse the credential helper output
	var creds struct {
		ServerURL string `json:"ServerURL"`
		Username  string `json:"Username"`
		Secret    string `json:"Secret"`
	}

	if err := json.Unmarshal(output, &creds); err != nil {
		return authConfig, fmt.Errorf("failed to parse credential helper output: %w", err)
	}

	authConfig.Username = creds.Username
	authConfig.Password = creds.Secret
	authConfig.ServerAddress = creds.ServerURL

	slog.Debug("Loaded credentials from credential store", "username", authConfig.Username, "store", store, "registry", registryURL)
	return authConfig, nil
}

type dockerHubResponse struct {
	Count   int    `json:"count"`
	Next    string `json:"next"`
	Results []struct {
		Name string `json:"name"`
	} `json:"results"`
}

func fetchOfficialImages() ([]string, error) {
	var allImages []string
	url := "https://hub.docker.com/v2/repositories/library/?page_size=100"
	page := 1

	for url != "" {
		slog.Debug("Fetching official images", "page", page, "url", url)
		resp, err := http.Get(url)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch from Docker Hub: %w", err)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to read response: %w", err)
		}
		resp.Body.Close()

		var data dockerHubResponse
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}

		slog.Debug("Fetched official images page", "page", page, "count", len(data.Results), "total", data.Count)
		for _, result := range data.Results {
			allImages = append(allImages, result.Name)
		}

		url = data.Next
		page++
	}

	sort.Strings(allImages)
	slog.Debug("Fetched all official images", "total", len(allImages))
	return allImages, nil
}
