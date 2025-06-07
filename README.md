# SonarCloud MCP Server

An MCP server that provides tools for fetching SonarCloud issues related to pull requests.

**Example prompt:**
> Fetch the list of OPEN or ACCEPTED issues from sonarcloud for this PR, which are assigned to **\_\_me\_\_**, fix them and push the changes to this PR.

Emphasis on the **\_\_me\_\_** part, which is a special value in the sonarcloud API to reference the current user (token owner). You can stick this in your `.claude/tools` folder as `sonarcloud-issues.md` to have a shortcut which requests claude code to fetch and fix issues from SonarCloud.


## Features

- Fetch issues from SonarCloud for specific pull requests
- Filter by organization, project, and PR number
- Supports authentication via API token
- Returns formatted issue data with severity, type, and location information

## Installation

### Prerequisite: Generate a SonarCloud API token
Follow the instructions in the [SonarCloud documentation](https://docs.sonarsource.com/sonarqube-cloud/managing-your-account/managing-tokens/) to generate a SonarCloud API token.

### Option 1: Docker (Recommended)

```bash
# Build the Docker image
npm run docker:build

# Or build directly
docker build -t sonarcloud-mcp .
```

### Option 2: Local Installation

```bash
npm ci
npm run build
```

## Usage

### Docker Usage
Run via docker:
```bash
docker run -i --rm \
  -e SONARCLOUD_TOKEN=your_token_here \
  -e SONARCLOUD_ORGANISATION=your_organisation_here \
  -e SONARCLOUD_PROJECT_KEY=your_project_key_here \
  sonarcloud-mcp
```

### Local Usage

Export the required environment variables and run the server:
```bash
export SONARCLOUD_TOKEN=your_token_here
export SONARCLOUD_ORGANISATION=your_organisation_here
export SONARCLOUD_PROJECT_KEY=your_project_key_here
npm start
```

### Environment Variables

- `SONARCLOUD_TOKEN`: Your SonarCloud API token (required)j
- `SONARCLOUD_ORGANISATION`: Your SonarCloud organization key (optional, can be passed as a parameter)
- `SONARCLOUD_PROJECT_KEY`: Your SonarCloud project key (optional, can be passed as a parameter)


## Claude Desktop / Claude Code Integration

### Docker Configuration (Recommended)

Add to your `claude_desktop_config.json` or `claude.json`:

```json
{
  "mcpServers": {
    "sonarcloud": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-e",
        "SONARCLOUD_TOKEN",
        "-e",
        "SONARCLOUD_ORGANISATION",
        "-e",
        "SONARCLOUD_PROJECT_KEY",
        "sonarcloud-mcp"
      ],
      "env": {
        "SONARCLOUD_TOKEN": "<your token here>",
        "SONARCLOUD_ORGANISATION": "<your organisation here>",
        "SONARCLOUD_PROJECT_KEY": "<your project key here>"
      }
    }
  }
}
```

### Local Configuration

Add to your `claude_desktop_config.json` or `claude.json`:

```json
{
  "mcpServers": {
    "sonarcloud-mcp": {
      "command": "node",
      "args": [
        "/path/to/sonarcloud_mcp/dist/index.js"
      ],
      "env": {
        "SONARCLOUD_TOKEN": "<your token here>",
        "SONARCLOUD_ORGANISATION": "<your organisation here>",
        "SONARCLOUD_PROJECT_KEY": "<your project key here>"
      }
    }
  }
}
```

### Available Tools
- `fetch_sonarcloud_issues`: Fetches SonarCloud issues for a specific pull request.

