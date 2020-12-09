package tests

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/lindell/multi-gitter/internal/domain"

	"github.com/lindell/multi-gitter/cmd"
	"github.com/lindell/multi-gitter/tests/vcmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStory tests the common usecase: run, status, merge, status
func TestStory(t *testing.T) {
	vcMock := &vcmock.VersionController{}
	cmd.OverrideVersionController = vcMock

	tmpDir, err := ioutil.TempDir(os.TempDir(), "multi-git-test-run-")
	defer os.RemoveAll(tmpDir)
	assert.NoError(t, err)

	workingDir, err := os.Getwd()
	assert.NoError(t, err)

	changeRepo := createRepo(t, "should-change", "i like apples")
	changeRepo2 := createRepo(t, "should-change-2", "i like my apple")
	noChangeRepo := createRepo(t, "should-not-change", "i like oranges")
	vcMock.AddRepository(changeRepo)
	vcMock.AddRepository(changeRepo2)
	vcMock.AddRepository(noChangeRepo)

	runOutFile := path.Join(tmpDir, "run-log.txt")

	command := cmd.RootCmd()
	command.SetArgs([]string{"run",
		"--output", runOutFile,
		"--author-name", "Test Author",
		"--author-email", "test@example.com",
		"-B", "custom-branch-name",
		"-m", "test",
		fmt.Sprintf(`go run %s`, path.Join(workingDir, "scripts/changer/main.go")),
	})
	err = command.Execute()
	assert.NoError(t, err)

	// Verify that the data of the original branch is intact
	data, err := ioutil.ReadFile(path.Join(changeRepo.Path, fileName))
	assert.NoError(t, err)
	assert.Equal(t, []byte("i like apples"), data)

	// Verify that the new branch is changed
	changeBranch(t, changeRepo.Path, "custom-branch-name", false)
	data, err = ioutil.ReadFile(path.Join(changeRepo.Path, fileName))
	assert.NoError(t, err)
	assert.Equal(t, []byte("i like bananas"), data)

	// Verify that the output was correct
	runOutData, err := ioutil.ReadFile(runOutFile)
	require.NoError(t, err)
	assert.Equal(t, string(runOutData), `No data was changed:
  should-not-change
Repositories with a successful run:
  should-change
  should-change-2
`)

	//
	// Status
	//
	statusOutFile := path.Join(tmpDir, "status-log.txt")

	command = cmd.RootCmd()
	command.SetArgs([]string{"status",
		"--output", statusOutFile,
		"-B", "custom-branch-name",
	})
	err = command.Execute()
	assert.NoError(t, err)

	// Verify that the output was correct
	statusOutData, err := ioutil.ReadFile(statusOutFile)
	require.NoError(t, err)
	assert.Equal(t, "should-change/XX: Pending\nshould-change-2/XX: Pending\n", string(statusOutData))

	// One of the created PRs is set to succeeded
	vcMock.SetPRStatus("should-change", "custom-branch-name", domain.PullRequestStatusSuccess)

	//
	// Merge
	//
	mergeLogFile := path.Join(tmpDir, "merge-log.txt")

	command = cmd.RootCmd()
	command.SetArgs([]string{"merge",
		"--log-file", mergeLogFile,
		"-B", "custom-branch-name",
	})
	err = command.Execute()
	assert.NoError(t, err)

	// Verify that the output was correct
	mergeLogData, err := ioutil.ReadFile(mergeLogFile)
	require.NoError(t, err)
	assert.Contains(t, string(mergeLogData), "Merging 1 pull requests")
	assert.Contains(t, string(mergeLogData), "Merging repo=should-change/XX")

	//
	// After Merge Status
	//
	afterMergeStatusOutFile := path.Join(tmpDir, "after-merge-status-log.txt")

	command = cmd.RootCmd()
	command.SetArgs([]string{"status",
		"--output", afterMergeStatusOutFile,
		"-B", "custom-branch-name",
	})
	err = command.Execute()
	assert.NoError(t, err)

	// Verify that the output was correct
	afterMergeStatusOutData, err := ioutil.ReadFile(afterMergeStatusOutFile)
	require.NoError(t, err)
	assert.Equal(t, "should-change/XX: Merged\nshould-change-2/XX: Pending\n", string(afterMergeStatusOutData))

	//
	// Close
	//
	closeLogFile := path.Join(tmpDir, "close-log.txt")

	command = cmd.RootCmd()
	command.SetArgs([]string{"close",
		"--log-file", closeLogFile,
		"-B", "custom-branch-name",
	})
	err = command.Execute()
	assert.NoError(t, err)

	// Verify that the output was correct
	closeLogData, err := ioutil.ReadFile(closeLogFile)
	require.NoError(t, err)
	assert.Contains(t, string(closeLogData), "Closing 1 pull request")
	assert.Contains(t, string(closeLogData), "Closing repo=should-change-2/XX")

	//
	// After Close Status
	//
	afterCloseStatusOutFile := path.Join(tmpDir, "after-close-status-log.txt")

	command = cmd.RootCmd()
	command.SetArgs([]string{"status",
		"--output", afterCloseStatusOutFile,
		"-B", "custom-branch-name",
	})
	err = command.Execute()
	assert.NoError(t, err)

	// Verify that the output was correct
	afterCloseStatusOutData, err := ioutil.ReadFile(afterCloseStatusOutFile)
	require.NoError(t, err)
	assert.Equal(t, "should-change/XX: Merged\nshould-change-2/XX: Closed\n", string(afterCloseStatusOutData))
}