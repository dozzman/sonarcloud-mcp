#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

interface SonarCloudIssue {
  key: string;
  rule: string;
  severity: string;
  component: string;
  project: string;
  line?: number;
  hash?: string;
  textRange?: {
    startLine: number;
    endLine: number;
    startOffset: number;
    endOffset: number;
  };
  flows?: any[];
  status: string;
  message: string;
  effort?: string;
  debt?: string;
  tags?: string[];
  creationDate: string;
  updateDate: string;
  type: string;
}

interface SonarCloudResponse {
  total: number;
  p: number;
  ps: number;
  paging: {
    pageIndex: number;
    pageSize: number;
    total: number;
  };
  effortTotal: number;
  debtTotal: number;
  issues: SonarCloudIssue[];
  components: any[];
  organizations: any[];
  facets: any[];
}

interface IssueSummary {
  totalIssues: number;
  criticalIssues: number;
  highImpactIssues: number;
  mediumImpactIssues: number;
  lowImpactIssues: number;
  infoIssues: number;
  bugCount: number;
  vulnerabilityCount: number;
  codeSmellCount: number;
  securityHotspotCount: number;
  openIssues: number;
  confirmedIssues: number;
  totalDebt: string;
  totalEffort: string;
  topRules: Array<{
    rule: string;
    count: number;
  }>;
  filesAffected: number;
}

class SonarCloudMCPServer {
  private server: Server;

  constructor() {
    this.server = new Server(
      {
        name: "sonarcloud-mcp",
        version: "1.0.0",
      },
      {
        capabilities: {
          tools: {},
        },
      },
    );

    this.setupToolHandlers();
  }

  private setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: "fetch_sonarcloud_issues",
            description: "Fetch SonarCloud issues for a specific pull request",
            inputSchema: {
              type: "object",
              properties: {
                additionalFields: {
                  type: "array",
                  items: {
                    type: "string",
                    enum: ["_all", "comments", "languages", "actionPlans", "rules", "ruleDescriptionContextKey", "transitions", "actions", "users"]
                  },
                  description: "Comma-separated list of the optional fields to be returned in response. Action plans are dropped in 5.5, it is not returned in the response.",
                },
                asc: {
                  type: "boolean",
                  description: "Ascending sort (default: true)",
                },
                assigned: {
                  type: "boolean",
                  description: "To retrieve assigned or unassigned issues",
                },
                assignees: {
                  type: "array",
                  items: {
                    type: "string"
                  },
                  description: "Comma-separated list of assignee logins. The value '__me__' can be used as a placeholder for user who performs the request",
                },
                author: {
                  type: "array",
                  items: {
                    type: "string"
                  },
                  description: "SCM accounts. To set several values, the parameter must be called once for each value.",
                },
                branch: {
                  type: "string",
                  description: "Branch key",
                },
                cleanCodeAttributeCategories: {
                  type: "array",
                  items: {
                    type: "string",
                    enum: ["ADAPTABLE", "CONSISTENT", "INTENTIONAL", "RESPONSIBLE"]
                  },
                  description: "Comma-separated list of clean code attribute categories.",
                },
                componentKeys: {
                  type: "array",
                  items: {
                    type: "string"
                  },
                  description: "Comma-separated list of component keys. Retrieve issues associated to a specific list of components (and all its descendants). A component can be a project, directory or file.",
                },
                createdAfter: {
                  type: "string",
                  description: "To retrieve issues created after the given date (inclusive). Either a date (server timezone) or datetime can be provided. If this parameter is set, createdSince must not be set",
                },
                createdAt: {
                  type: "string",
                  description: "Datetime to retrieve issues created during a specific analysis",
                },
                createdBefore: {
                  type: "string",
                  description: "To retrieve issues created before the given date (inclusive). Either a date (server timezone) or datetime can be provided.",
                },
                createdInLast: {
                  type: "string",
                  description: "To retrieve issues created during a time span before the current time (exclusive). Accepted units are 'y' for year, 'm' for month, 'w' for week and 'd' for day. If this parameter is set, createdAfter must not be set",
                },
                cwe: {
                  type: "array",
                  items: {
                    type: "string"
                  },
                  description: "Comma-separated list of CWE identifiers. Use 'unknown' to select issues not associated to any CWE.",
                },
                facets: {
                  type: "array",
                  items: {
                    type: "string",
                    enum: [
                      "projects",
                      "moduleUuids",
                      "fileUuids",
                      "assigned_to_me",
                      "severities",
                      "statuses",
                      "issueStatuses",
                      "resolutions",
                      "rules",
                      "assignees",
                      "author",
                      "directories",
                      "languages",
                      "tags",
                      "types",
                      "owaspTop10",
                      "owaspTop10-2021",
                      "cwe",
                      "createdAt",
                      "sonarsourceSecurity",
                      "impactSoftwareQualities",
                      "impactSeverities",
                      "cleanCodeAttributeCategories",
                    ],
                  },
                  description: "Comma-separated list of the facets to be computed. No facet is computed by default.",
                },
                impactSeverities: {
                  type: "array",
                  items: {
                    type: "string",
                    enum: ["INFO", "LOW", "MEDIUM", "HIGH", "BLOCKER"],
                  },
                  description: "Comma-separated list of impact severities.",
                },
                impactSoftwareQualities: {
                  type: "array",
                  items: {
                    type: "string",
                    enum: ["MAINTAINABILITY", "RELIABILITY", "SECURITY"]
                  },
                  description: "Comma-separated list of software qualities.",
                },
                issueStatuses: {
                  type: "array",
                  items: {
                    type: "string",
                    enum: [
                      "OPEN",
                      "CONFIRMED",
                      "FALSE_POSITIVE",
                      "ACCEPTED",
                      "FIXED",
                    ],
                  },
                  description: "Comma-separated list of issue statuses",
                },
                issues: {
                  type: "array",
                  items: {
                    type: "string"
                  },
                  description: "Comma-separated list of issue keys",
                },
                languages: {
                  type: "array",
                  items: {
                    type: "string"
                  },
                  description: "Comma-separated list of languages. Available since 4.4",
                },
                onComponentOnly: {
                  type: "boolean",
                  description: "Return only issues at a component's level, not on its descendants (modules, directories, files, etc). This parameter is only considered when componentKeys or componentUuids is set. (default: false)",
                },
                organization: {
                  type: "string",
                  description: "Organization key",
                },
                owaspTop10: {
                  type: "array",
                  items: {
                    type: "string",
                    enum: ["a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10"]
                  },
                  description: "Comma-separated list of OWASP Top 10 lowercase categories.",
                },
                "owaspTop10-2021": {
                  type: "array",
                  items: {
                    type: "string",
                    enum: ["a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10"]
                  },
                  description: "Comma-separated list of OWASP Top 10 - 2021 lowercase categories.",
                },
                p: {
                  type: "number",
                  description: "1-based page number (default: 1)",
                  minimum: 1,
                },
                ps: {
                  type: "number",
                  description: "Page size. Must be greater than 0 and less or equal than 500 (default: 100)",
                  minimum: 1,
                  maximum: 500,
                },
                pullRequest: {
                  type: "string",
                  description: "Pull request id",
                },
                resolved: {
                  type: "boolean",
                  description: "To match resolved or unresolved issues",
                },
                rules: {
                  type: "array",
                  items: {
                    type: "string"
                  },
                  description: "Comma-separated list of coding rule keys. Format is <repository>:<rule>",
                },
                s: {
                  type: "string",
                  enum: [
                    "CREATION_DATE",
                    "ASSIGNEE",
                    "STATUS",
                    "UPDATE_DATE",
                    "CLOSE_DATE",
                    "HOTSPOTS",
                    "FILE_LINE",
                    "SEVERITY",
                  ],
                  description: "Sort field",
                },
                sinceLeakPeriod: {
                  type: "boolean",
                  description: "To retrieve issues created since the leak period. If this parameter is set to a truthy value, createdAfter must not be set and one component id or key must be provided. (default: false)",
                },
                sonarsourceSecurity: {
                  type: "array",
                  items: {
                    type: "string",
                    enum: [
                      "buffer-overflow", "permission", "sql-injection", "command-injection", "path-traversal-injection",
                      "ldap-injection", "xpath-injection", "rce", "dos", "ssrf", "csrf", "xss", "log-injection",
                      "http-response-splitting", "open-redirect", "xxe", "object-injection", "weak-cryptography",
                      "auth", "insecure-conf", "encrypt-data", "traceability", "file-manipulation", "others"
                    ]
                  },
                  description: "Comma-separated list of SonarSource security categories. Use 'others' to select issues not associated with any category",
                },
                tags: {
                  type: "array",
                  items: {
                    type: "string"
                  },
                  description: "Comma-separated list of tags.",
                },
                token: {
                  type: "string",
                  description: "SonarCloud API token (optional if set in environment)",
                },
              },
              required: [],
            },
          },
          {
            name: "summarize_sonarcloud_issues",
            description: "Get a high-level summary of SonarCloud issues for a PR",
            inputSchema: {
              type: "object",
              properties: {
                pullRequest: {
                  type: "string",
                  description: "Pull request id",
                },
                token: {
                  type: "string",
                  description: "SonarCloud API token (optional if set in environment)",
                },
                impactSeverities: {
                  type: "array",
                  items: {
                    type: "string",
                    enum: ["INFO", "LOW", "MEDIUM", "HIGH", "BLOCKER"],
                  },
                  description: "Comma-separated list of impact severities.",
                },
                sinceLeakPeriod: {
                  type: "boolean",
                  description: "To retrieve issues created since the leak period. If this parameter is set to a truthy value, createdAfter must not be set and one component id or key must be provided. (default: false)",
                },
                issueStatuses: {
                  type: "array",
                  items: {
                    type: "string",
                    enum: [
                      "OPEN",
                      "CONFIRMED",
                      "FALSE_POSITIVE",
                      "ACCEPTED",
                      "FIXED",
                    ],
                  },
                  description: "Comma-separated list of issue statuses",
                },
              },
              required: [],
            },
          },
        ],
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      if (name === "fetch_sonarcloud_issues") {
        return await this.fetchSonarCloudIssues(args);
      }
      
      if (name === "summarize_sonarcloud_issues") {
        return await this.summarizeSonarCloudIssues(args);
      }

      throw new Error(`Unknown tool: ${name}`);
    });
  }

  private async fetchSonarCloudIssues(args: any) {
    const {
      additionalFields,
      asc = true,
      assigned,
      assignees,
      author,
      branch,
      cleanCodeAttributeCategories,
      componentKeys,
      createdAfter,
      createdAt,
      createdBefore,
      createdInLast,
      cwe,
      facets,
      impactSeverities,
      impactSoftwareQualities,
      issueStatuses,
      issues,
      languages,
      onComponentOnly = false,
      organization,
      owaspTop10,
      "owaspTop10-2021": owaspTop102021,
      p = 1,
      ps = 100,
      pullRequest,
      resolved,
      rules,
      s,
      sinceLeakPeriod = false,
      sonarsourceSecurity,
      tags,
      token,
    } = args;

    const apiToken = token || process.env.SONARCLOUD_TOKEN;
    const orgFromEnv =
      organization ||
      process.env.SONARCLOUD_ORGANIZATION ||
      process.env.SONARCLOUD_ORGANISATION;
    const projectKey = process.env.SONARCLOUD_PROJECT_KEY;

    if (!apiToken) {
      throw new Error(
        "SonarCloud API token is required. Provide it as a parameter or set SONARCLOUD_TOKEN environment variable.",
      );
    }

    try {
      const url = new URL("https://sonarcloud.io/api/issues/search");
      
      // Helper function to add array parameters
      const addArrayParam = (paramName: string, value: string[] | undefined) => {
        if (value && value.length > 0) {
          url.searchParams.set(paramName, value.join(","));
        }
      };
      
      // Helper function to add string parameters
      const addStringParam = (paramName: string, value: string | undefined) => {
        if (value !== undefined && value !== null && value !== "") {
          url.searchParams.set(paramName, value.toString());
        }
      };
      
      // Helper function to add boolean parameters
      const addBooleanParam = (paramName: string, value: boolean | undefined) => {
        if (value !== undefined && value !== null) {
          url.searchParams.set(paramName, value.toString());
        }
      };
      
      // Helper function to add number parameters
      const addNumberParam = (paramName: string, value: number | undefined) => {
        if (value !== undefined && value !== null) {
          url.searchParams.set(paramName, value.toString());
        }
      };

      // Add all parameters exactly as per API specification
      addArrayParam("additionalFields", additionalFields);
      addBooleanParam("asc", asc);
      addBooleanParam("assigned", assigned);
      addArrayParam("assignees", assignees);
      
      // Author parameter needs special handling as it can be called multiple times
      if (author && author.length > 0) {
        author.forEach((authorValue: string) => {
          url.searchParams.append("author", authorValue);
        });
      }
      
      addStringParam("branch", branch);
      addArrayParam("cleanCodeAttributeCategories", cleanCodeAttributeCategories);
      
      // Set componentKeys from parameter or fallback to project key from env
      if (componentKeys && componentKeys.length > 0) {
        addArrayParam("componentKeys", componentKeys);
      } else if (projectKey) {
        url.searchParams.set("componentKeys", projectKey);
      }
      
      addStringParam("createdAfter", createdAfter);
      addStringParam("createdAt", createdAt);
      addStringParam("createdBefore", createdBefore);
      addStringParam("createdInLast", createdInLast);
      addArrayParam("cwe", cwe);
      addArrayParam("facets", facets);
      addArrayParam("impactSeverities", impactSeverities);
      addArrayParam("impactSoftwareQualities", impactSoftwareQualities);
      addArrayParam("issueStatuses", issueStatuses);
      addArrayParam("issues", issues);
      addArrayParam("languages", languages);
      addBooleanParam("onComponentOnly", onComponentOnly);
      
      // Set organization from parameter or environment
      if (orgFromEnv) {
        url.searchParams.set("organization", orgFromEnv);
      }
      
      addArrayParam("owaspTop10", owaspTop10);
      addArrayParam("owaspTop10-2021", owaspTop102021);
      addNumberParam("p", p);
      addNumberParam("ps", ps);
      addStringParam("pullRequest", pullRequest);
      addBooleanParam("resolved", resolved);
      addArrayParam("rules", rules);
      addStringParam("s", s);
      addBooleanParam("sinceLeakPeriod", sinceLeakPeriod);
      addArrayParam("sonarsourceSecurity", sonarsourceSecurity);
      addArrayParam("tags", tags);

      const response = await fetch(url.toString(), {
        headers: {
          Authorization: `Bearer ${apiToken}`,
          Accept: "application/json",
        },
      });

      if (!response.ok) {
        throw new Error(
          `SonarCloud API error: ${response.status} ${response.statusText}`,
        );
      }

      const data: SonarCloudResponse = await response.json();

      const formattedIssues = data.issues.map((issue) => ({
        key: issue.key,
        rule: issue.rule,
        severity: issue.severity,
        type: issue.type,
        status: issue.status,
        message: issue.message,
        component: issue.component,
        line: issue.line,
        effort: issue.effort,
        tags: issue.tags,
        creationDate: issue.creationDate,
        updateDate: issue.updateDate,
      }));

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                summary: {
                  total: data.total,
                  organization: orgFromEnv,
                  projectKey,
                  pullRequest,
                },
                pagination: {
                  page: data.paging.pageIndex,
                  pageSize: data.paging.pageSize,
                  total: data.paging.total,
                },
                facets: data.facets,
                issues: formattedIssues,
              },
              null,
              2,
            ),
          },
        ],
      };
    } catch (error: any) {
      throw new Error(`Failed to fetch SonarCloud issues: ${error.message}`);
    }
  }

  private async summarizeSonarCloudIssues(args: any): Promise<any> {
    // Get the raw issues first
    const issuesResponse = await this.fetchSonarCloudIssues({
      ...args,
      additionalFields: ["_all"],
      facets: ["issueStatuses", "impactSeverities", "types", "rules"],
      ps: 500 // Get more issues for better summary
    });
    
    const data = JSON.parse(issuesResponse.content[0].text);
    const issues = data.issues;
    
    // Create summary
    const summary: IssueSummary = {
      totalIssues: data.summary.total,
      criticalIssues: issues.filter((i: any) => i.severity === "BLOCKER").length,
      highImpactIssues: issues.filter((i: any) => i.severity === "CRITICAL" || i.severity === "MAJOR").length,
      mediumImpactIssues: issues.filter((i: any) => i.severity === "MINOR").length,
      lowImpactIssues: issues.filter((i: any) => i.severity === "INFO").length,
      infoIssues: issues.filter((i: any) => i.severity === "INFO").length,
      bugCount: issues.filter((i: any) => i.type === "BUG").length,
      vulnerabilityCount: issues.filter((i: any) => i.type === "VULNERABILITY").length,
      codeSmellCount: issues.filter((i: any) => i.type === "CODE_SMELL").length,
      securityHotspotCount: issues.filter((i: any) => i.type === "SECURITY_HOTSPOT").length,
      openIssues: issues.filter((i: any) => i.status === "OPEN").length,
      confirmedIssues: issues.filter((i: any) => i.status === "CONFIRMED").length,
      totalDebt: data.debtTotal?.toString() || "0",
      totalEffort: data.effortTotal?.toString() || "0",
      topRules: this.getTopRules(issues),
      filesAffected: new Set(issues.map((i: any) => i.component)).size,
    };
    
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(summary, null, 2),
        },
      ],
    };
  }
  
  private getTopRules(issues: any[]): Array<{rule: string; count: number}> {
    const ruleCounts = issues.reduce((acc, issue) => {
      acc[issue.rule] = (acc[issue.rule] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    return Object.entries(ruleCounts)
      .sort(([,a], [,b]) => (b as number) - (a as number))
      .slice(0, 10)
      .map(([rule, count]) => ({rule, count: count as number}));
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
  }
}

const server = new SonarCloudMCPServer();
server.run().catch(console.error);
