import * as Sarif from 'sarif';

export function createSarifOutputForContainers(testResult): Sarif.Log {
  const sarifRes: Sarif.Log = {
    version: '2.1.0',
    runs: [],
  };

  testResult.forEach((testResult) => {
    sarifRes.runs.push({
      tool: getTool(testResult),
      results: getResults(testResult),
    });
  });

  return sarifRes;
}

export function getTool(testResult): Sarif.Tool {
  const tool: Sarif.Tool = {
    driver: {
      name: 'Snyk Container',
      rules: [],
    },
  };

  if (!testResult.vulnerabilities) {
    return tool;
  }

  const pushedIds: string[] = [];
  testResult.vulnerabilities.forEach((vuln) => {
    if (pushedIds.includes(vuln.id)) {
      return;
    }
    const level = vuln.severity == 'high' ? 'error' : 'warning';
    const cve = vuln['identifiers']['CVE'][0];
    tool.driver.rules?.push({
      id: vuln.id,
      shortDescription: {
        text: `${vuln.severity} severity ${vuln.title} vulnerability in ${vuln.packageName}`,
      },
      fullDescription: {
        text: cve
          ? `(${cve}) ${vuln.name}@${vuln.version}`
          : `${vuln.name}@${vuln.version}`,
      },
      help: {
        text: '',
        markdown: vuln.description,
      },
      defaultConfiguration: {
        level: level,
      },
      properties: {
        tags: ['security', ...vuln.identifiers.CWE],
      },
    });
    pushedIds.push(vuln.id);
  });
  return tool;
}

export function getResults(testResult): Sarif.Result[] {
  const results: Sarif.Result[] = [];

  testResult.vulnerabilities.forEach((vuln) => {
    results.push({
      ruleId: vuln.id,
      message: {
        text: `This file introduces a vulnerable ${vuln.packageName} package with a ${vuln.severity} severity vulnerability.`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: testResult.displayTargetFile,
            },
            region: {
              startLine: vuln.lineNumber || 1,
            },
          },
        },
      ],
    });
  });
  return results;
}
