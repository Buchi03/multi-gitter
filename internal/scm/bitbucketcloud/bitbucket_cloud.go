package bitbucketcloud

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"

	bitbucketv2 "github.com/ktrysmt/go-bitbucket"
	"github.com/lindell/multi-gitter/internal/scm"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
)

const (
	cloneHTTPType = "http"
	cloneSSHType  = "ssh"
	stateMerged   = "MERGED"
	stateDeclined = "DECLINED"
)

// New create a new BitbucketCloud client
func New(username, token, baseURL string, insecure bool, sshAuth bool, transportMiddleware func(http.RoundTripper) http.RoundTripper, repoListing RepositoryListing) (*BitbucketCloud, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("token is empty")
	}

	if strings.TrimSpace(baseURL) == "" {
		return nil, errors.New("base url is empty")
	}

	bitbucketBaseURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	if !strings.HasSuffix(bitbucketBaseURL.Path, "/rest") {
		bitbucketBaseURL.Path = path.Join(bitbucketBaseURL.Path, "/rest")
	}

	bitbucketCloud := &BitbucketCloud{}
	bitbucketCloud.RepositoryListing = repoListing
	bitbucketCloud.baseURL = bitbucketBaseURL
	bitbucketCloud.username = username
	bitbucketCloud.token = token
	bitbucketCloud.sshAuth = sshAuth
	bitbucketCloud.httpClient = &http.Client{
		Transport: transportMiddleware(&http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, // nolint: gosec
		}),
	}
	bitbucketCloud.config = bitbucketv2.NewConfiguration(bitbucketBaseURL.String(), func(config *bitbucketv2.Configuration) {
		config.AddDefaultHeader("Authorization", fmt.Sprintf("Bearer %s", token))
		config.HTTPClient = &http.Client{
			Transport: transportMiddleware(&http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, // nolint: gosec
			}),
		}
	})

	return bitbucketCloud, nil
}

func newClient(ctx context.Context, config *bitbucketv2.Configuration) *bitbucketv2.APIClient {
	return bitbucketv2.NewAPIClient(
		ctx,
		config,
	)
}

// BitbucketCloud is a SCM instance of Bitbucket Cloud
type BitbucketCloud struct {
	RepositoryListing
	baseURL         *url.URL
	username, token string
	sshAuth         bool
	config          *bitbucketv2.Configuration
	httpClient      *http.Client
}

// RepositoryListing contains information about which repositories that should be fetched
type RepositoryListing struct {
	Projects     []string
	Users        []string
	Repositories []RepositoryReference
}

// RepositoryReference contains information to be able to reference a repository
type RepositoryReference struct {
	ProjectKey string
	Name       string
}

// ParseRepositoryReference parses a GiteaRepository reference from the format "projectKey/repoName"
func ParseRepositoryReference(val string) (RepositoryReference, error) {
	split := strings.Split(val, "/")
	if len(split) != 2 {
		return RepositoryReference{}, fmt.Errorf("could not parse repository reference: %s", val)
	}
	return RepositoryReference{
		ProjectKey: split[0],
		Name:       split[1],
	}, nil
}

// String returns the string representation of a repo reference
func (rr RepositoryReference) String() string {
	return fmt.Sprintf("%s/%s", rr.ProjectKey, rr.Name)
}

// GetRepositories Should get repositories based on the scm configuration
func (b *BitbucketCloud) GetRepositories(ctx context.Context) ([]scm.Repository, error) {
	client := newClient(ctx, b.config)

	bitbucketRepositories, err := b.getRepositories(client)
	if err != nil {
		return nil, err
	}

	repositories := make([]scm.Repository, 0, len(bitbucketRepositories))

	// Get default branches and create repo interfaces
	for _, bitbucketRepository := range bitbucketRepositories {
		response, getDefaultBranchErr := client.DefaultApi.GetDefaultBranch(bitbucketRepository.Project.Key, bitbucketRepository.Slug)
		if getDefaultBranchErr != nil {
			return nil, getDefaultBranchErr
		}

		var defaultBranch bitbucketv2.Branch
		err = mapstructure.Decode(response.Values, &defaultBranch)
		if err != nil {
			return nil, err
		}

		repo, repoErr := b.convertRepository(bitbucketRepository, defaultBranch)
		if repoErr != nil {
			return nil, repoErr
		}

		repositories = append(repositories, *repo)
	}

	return repositories, nil
}

func (b *BitbucketCloud) getRepositories(client *bitbucketv2.APIClient) ([]*bitbucketv2.Repository, error) {
	var bitbucketRepositories []*bitbucketv2.Repository

	for _, project := range b.Projects {
		repos, err := b.getProjectRepositories(client, project)
		if err != nil {
			return nil, err
		}

		bitbucketRepositories = append(bitbucketRepositories, repos...)
	}

	for _, user := range b.Users {
		repos, err := b.getProjectRepositories(client, user)
		if err != nil {
			return nil, err
		}

		bitbucketRepositories = append(bitbucketRepositories, repos...)
	}

	for _, repositoryRef := range b.Repositories {
		repo, err := b.getRepository(client, repositoryRef.ProjectKey, repositoryRef.Name)
		if err != nil {
			return nil, err
		}

		bitbucketRepositories = append(bitbucketRepositories, repo)
	}

	// Remove duplicate repos
	repositoryMap := make(map[int]*bitbucketv2.Repository, len(bitbucketRepositories))
	for _, bitbucketRepository := range bitbucketRepositories {
		repositoryMap[bitbucketRepository.ID] = bitbucketRepository
	}
	bitbucketRepositories = make([]*bitbucketv2.Repository, 0, len(repositoryMap))
	for _, repo := range repositoryMap {
		bitbucketRepositories = append(bitbucketRepositories, repo)
	}
	sort.Slice(bitbucketRepositories, func(i, j int) bool {
		return bitbucketRepositories[i].ID < bitbucketRepositories[j].ID
	})

	return bitbucketRepositories, nil
}

func (b *BitbucketCloud) getRepository(client *bitbucketv2.APIClient, projectKey, repositorySlug string) (*bitbucketv2.Repository, error) {
	response, err := client.DefaultApi.GetRepository(projectKey, repositorySlug)
	if err != nil {
		return nil, err
	}

	var bitbucketRepository bitbucketv2.Repository
	err = mapstructure.Decode(response.Values, &bitbucketRepository)
	if err != nil {
		return nil, err
	}

	return &bitbucketRepository, nil
}

func (b *BitbucketCloud) getProjectRepositories(client *bitbucketv2.APIClient, projectKey string) ([]*bitbucketv2.Repository, error) {
	params := map[string]interface{}{"start": 0, "limit": 25}

	var repositories []*bitbucketv2.Repository
	for {
		response, err := client.DefaultApi.GetRepositoriesWithOptions(projectKey, params)
		if err != nil {
			return nil, err
		}

		var pager bitbucketRepositoryPager
		err = mapstructure.Decode(response.Values, &pager)
		if err != nil {
			return nil, err
		}

		for _, repo := range pager.Values {
			r := repo
			repositories = append(repositories, &r)
		}

		if pager.IsLastPage {
			break
		}

		params["start"] = pager.NextPageStart
	}

	return repositories, nil
}

// CreatePullRequest Creates a pull request. The repo parameter will always originate from the same package
func (b *BitbucketCloud) CreatePullRequest(ctx context.Context, repo scm.Repository, prRepo scm.Repository, newPR scm.NewPullRequest) (scm.PullRequest, error) {
	r := repo.(repository)
	prR := prRepo.(repository)

	client := newClient(ctx, b.config)

	reviewers, err := b.getUsersWithLinks(newPR.Reviewers, client)
	if err != nil {
		return nil, err
	}

	response, err := client.DefaultApi.CreatePullRequest(r.project, r.name, bitbucketv2.PullRequest{
		Title:       newPR.Title,
		Description: newPR.Body,
		Reviewers:   reviewers,
		FromRef: bitbucketv2.PullRequestRef{
			ID: fmt.Sprintf("refs/heads/%s", newPR.Head),
			Repository: bitbucketv2.Repository{
				Slug: prR.name,
				Project: &bitbucketv2.Project{
					Key: prR.project,
				},
			},
		},
		ToRef: bitbucketv2.PullRequestRef{
			ID: fmt.Sprintf("refs/heads/%s", newPR.Base),
			Repository: bitbucketv2.Repository{
				Slug: r.name,
				Project: &bitbucketv2.Project{
					Key: r.project,
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create pull request for repository %s: %s", r.name, err)
	}

	pullRequestResp, err := bitbucketv2.GetPullRequestResponse(response)
	if err != nil {
		return nil, fmt.Errorf("unable to create pull request for repository %s: %s", r.name, err)
	}

	return newPullRequest(pullRequestResp), nil
}

func (b *BitbucketCloud) getUsersWithLinks(usernames []string, client *bitbucketv2.APIClient) ([]bitbucketv2.UserWithMetadata, error) {
	var usersWithMetadata []bitbucketv2.UserWithMetadata

	for _, username := range usernames {
		response, err := client.DefaultApi.GetUser(username)
		if err != nil {
			return nil, err
		}

		var userWithLinks bitbucketv2.UserWithLinks
		err = mapstructure.Decode(response.Values, &userWithLinks)
		if err != nil {
			return nil, err
		}

		usersWithMetadata = append(usersWithMetadata, bitbucketv2.UserWithMetadata{User: userWithLinks})
	}

	return usersWithMetadata, nil
}

// GetPullRequests Gets the latest pull requests from repositories based on the scm configuration
func (b *BitbucketCloud) GetPullRequests(ctx context.Context, branchName string) ([]scm.PullRequest, error) {
	client := newClient(ctx, b.config)

	repositories, err := b.getRepositories(client)
	if err != nil {
		return nil, err
	}

	var prs []scm.PullRequest
	for _, repo := range repositories {
		pr, getPullRequestErr := b.getPullRequest(client, branchName, repo.Project.Key, repo.Slug)
		if getPullRequestErr != nil {
			return nil, getPullRequestErr
		}
		if pr == nil {
			continue
		}

		convertedPR, err := b.convertPullRequest(client, repo.Project.Key, repo.Slug, branchName, pr)
		if err != nil {
			return nil, err
		}

		prs = append(prs, convertedPR)
	}

	return prs, nil
}

func (b *BitbucketCloud) convertPullRequest(client *bitbucketv2.APIClient, project, repoName, branchName string, pr *bitbucketv2.PullRequest) (pullRequest, error) {
	status, err := b.pullRequestStatus(client, project, repoName, pr)
	if err != nil {
		return pullRequest{}, err
	}

	return pullRequest{
		repoName:   repoName,
		project:    project,
		branchName: branchName,
		prProject:  pr.FromRef.Repository.Project.Key,
		prRepoName: pr.FromRef.Repository.Slug,
		number:     pr.ID,
		version:    pr.Version,
		guiURL:     pr.Links.Self[0].Href,
		status:     status,
	}, nil
}

func (b *BitbucketCloud) pullRequestStatus(client *bitbucketv2.APIClient, project, repoName string, pr *bitbucketv2.PullRequest) (scm.PullRequestStatus, error) {
	switch pr.State {
	case stateMerged:
		return scm.PullRequestStatusMerged, nil
	case stateDeclined:
		return scm.PullRequestStatusClosed, nil
	}

	response, err := client.DefaultApi.CanMerge(project, repoName, int64(pr.ID))
	if err != nil {
		return scm.PullRequestStatusUnknown, err
	}

	var merge bitbucketv2.MergeGetResponse
	err = mapstructure.Decode(response.Values, &merge)
	if err != nil {
		return scm.PullRequestStatusUnknown, err
	}

	if !merge.CanMerge {
		return scm.PullRequestStatusPending, nil
	}

	if merge.Conflicted {
		return scm.PullRequestStatusError, nil
	}

	return scm.PullRequestStatusSuccess, nil
}

func (b *BitbucketCloud) getPullRequest(client *bitbucketv2.APIClient, branchName, project, repoName string) (*bitbucketv2.PullRequest, error) {
	params := map[string]interface{}{"start": 0, "limit": 25}

	var pullRequests []bitbucketv2.PullRequest
	for {
		response, err := client.DefaultApi.GetPullRequestsPage(project, repoName, params)
		if err != nil {
			return nil, err
		}

		var pager bitbucketPullRequestPager
		err = mapstructure.Decode(response.Values, &pager)
		if err != nil {
			return nil, err
		}

		pullRequests = append(pullRequests, pager.Values...)

		if pager.IsLastPage {
			break
		}

		params["start"] = pager.NextPageStart
	}

	for _, pr := range pullRequests {
		if pr.FromRef.DisplayID == branchName {
			return &pr, nil
		}
	}

	return nil, nil
}

// GetOpenPullRequest gets a pull request for one specific repository
func (b *BitbucketCloud) GetOpenPullRequest(ctx context.Context, repo scm.Repository, branchName string) (scm.PullRequest, error) {
	r := repo.(repository)

	client := newClient(ctx, b.config)

	pr, err := b.getPullRequest(client, branchName, r.project, r.name)
	if err != nil {
		return nil, err
	}

	if pr == nil {
		return nil, nil
	}

	convertedPR, err := b.convertPullRequest(client, r.project, r.name, branchName, pr)
	if err != nil {
		return nil, err
	}

	return convertedPR, nil
}

// MergePullRequest Merges a pull request, the pr parameter will always originate from the same package
func (b *BitbucketCloud) MergePullRequest(ctx context.Context, pr scm.PullRequest) error {
	bitbucketPR := pr.(pullRequest)

	client := newClient(ctx, b.config)

	response, err := client.DefaultApi.GetPullRequest(bitbucketPR.project, bitbucketPR.repoName, bitbucketPR.number)
	if err != nil {
		if strings.Contains(err.Error(), "com.atlassian.bitbucket.pull.NoSuchPullRequestException") {
			return nil
		}
		return err
	}

	pullRequestResponse, err := bitbucketv2.GetPullRequestResponse(response)
	if err != nil {
		return err
	}

	if !pullRequestResponse.Open {
		return nil
	}

	mergeMap := make(map[string]interface{})
	mergeMap["version"] = pullRequestResponse.Version

	_, err = client.DefaultApi.Merge(bitbucketPR.project, bitbucketPR.repoName, bitbucketPR.number, mergeMap, nil, []string{"application/json"})
	if err != nil {
		return err
	}

	return b.deleteBranch(ctx, bitbucketPR)
}

// ClosePullRequest Close a pull request, the pr parameter will always originate from the same package
func (b *BitbucketCloud) ClosePullRequest(ctx context.Context, pr scm.PullRequest) error {
	bitbucketPR := pr.(pullRequest)

	client := newClient(ctx, b.config)

	_, err := client.DefaultApi.DeleteWithVersion(bitbucketPR.project, bitbucketPR.repoName, int64(bitbucketPR.number), int64(bitbucketPR.version))
	if err != nil {
		return err
	}

	return b.deleteBranch(ctx, bitbucketPR)
}

func (b *BitbucketCloud) deleteBranch(ctx context.Context, pr pullRequest) error {
	urlPath := *b.baseURL
	urlPath.Path = path.Join(urlPath.Path, "branch-utils/1.0/projects", pr.project, "repos", pr.repoName, "branches")

	body := bitbucketDeleteBranch{Name: path.Join("refs", "heads", pr.branchName), DryRun: false}
	bodyBytes, err := json.Marshal(&body)
	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, "DELETE", urlPath.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add(
		"Authorization",
		"Basic "+base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", b.username, b.token))),
	)

	response, err := b.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode >= 400 {
		buf := new(bytes.Buffer)
		_, readFromErr := buf.ReadFrom(response.Body)
		if readFromErr != nil {
			return readFromErr
		}

		return errors.Errorf("unable to delete branch: status code %d: %s", response.StatusCode, buf.String())
	}

	return nil
}

// ForkRepository forks a repository. If newOwner is set, use it, otherwise fork to the current user
func (b *BitbucketCloud) ForkRepository(_ context.Context, _ scm.Repository, _ string) (scm.Repository, error) {
	return nil, errors.New("forking not implemented for bitbucket cloud")
}

type bitbucketRepositoryPager struct {
	Size          int                      `json:"size"`
	Limit         int                      `json:"limit"`
	Start         int                      `json:"start"`
	NextPageStart int                      `json:"nextPageStart"`
	IsLastPage    bool                     `json:"isLastPage"`
	Values        []bitbucketv2.Repository `json:"values"`
}

type bitbucketPullRequestPager struct {
	Size          int                       `json:"size"`
	Limit         int                       `json:"limit"`
	Start         int                       `json:"start"`
	NextPageStart int                       `json:"nextPageStart"`
	IsLastPage    bool                      `json:"isLastPage"`
	Values        []bitbucketv2.PullRequest `json:"values"`
}

type bitbucketDeleteBranch struct {
	Name   string `json:"name"`
	DryRun bool   `json:"dryRun"`
}
