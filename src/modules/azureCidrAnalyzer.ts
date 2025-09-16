/*****************************************************************************
 *   Extension:   Microsoft Azure CIDRs Analyzer                             *
 *   Author:      elelabdev                                                  *
 *   Description: Query right from Visual Studio Code all Microsoft Azure    *
 *                subscriptions and search for specific CIDRs in use.        *
 *   Github:      https://github.com/elelabdev/microsoft-azure-cidr-analyzer *
 *                                                                           *
 *   Icon Author: elelab                                                     *
 *                                                                           *
 *   Copyright (C) 2025 elelab                                               *
 *   https://www.elelab.dev                                                  *
 *                                                                           *
 *   Licensed under the MIT License. See LICENSE file in the project         *
 *   root for details.                                                       *
 ****************************************************************************/

// src/modules/azureCidrAnalyzer.ts

// =========================================================================
// IMPORT libraries or modules
// =========================================================================
import * as vscode from 'vscode';
import { getNonce } from '../helpers/nonce';
import { exportCsv } from '../helpers/exporter';

const CONFIG_NAMESPACE = 'azureCidrAnalyzer';

// =========================================================================
// TYPES
// =========================================================================
type GraphResult = Record<string, unknown>;

interface SubscriptionInfo {
  id: string;
  name?: string;
}

interface LookupMessage {
  command: 'lookupCidr';
  cidr: string;
  subscriptions?: string[];
}

interface ExportMessage {
  command: 'exportCsv';
}

interface RequestSubscriptionsMessage {
  command: 'requestSubscriptions';
}

type IncomingMessage = LookupMessage | ExportMessage | RequestSubscriptionsMessage;

// =========================================================================
// EXPORT functions
// =========================================================================
export function openAzureCidrAnalyzer(context: vscode.ExtensionContext): void {
  const panel = vscode.window.createWebviewPanel(
    'azureCidrAnalyzer',
    'Azure CIDR Analyzer',
    vscode.ViewColumn.Beside,
    {
      enableScripts: true,
      retainContextWhenHidden: true,
      localResourceRoots: [
        vscode.Uri.joinPath(context.extensionUri, 'media', 'libs'),
        vscode.Uri.joinPath(context.extensionUri, 'media', 'common'),
        vscode.Uri.joinPath(context.extensionUri, 'media', 'module-azurecidranalyzer')
      ]
    }
  );

  const nonce = getNonce();
  const cspSource = panel.webview.cspSource;
  const elementsUri = panel.webview.asWebviewUri(
    vscode.Uri.joinPath(context.extensionUri, 'media', 'libs', 'vscode-elements', 'bundled.js')
  );
  const commonStyleUri = panel.webview.asWebviewUri(
    vscode.Uri.joinPath(context.extensionUri, 'media', 'common', 'css', 'style.css')
  );
  const styleUri = panel.webview.asWebviewUri(
    vscode.Uri.joinPath(context.extensionUri, 'media', 'module-azurecidranalyzer', 'style.css')
  );
  const scriptUri = panel.webview.asWebviewUri(
    vscode.Uri.joinPath(context.extensionUri, 'media', 'module-azurecidranalyzer', 'main.js')
  );

  panel.webview.html = showWebviewContent({
    nonce,
    cspSource,
    elementsSrc: elementsUri.toString(),
    commonStyleSrc: commonStyleUri.toString(),
    styleSrc: styleUri.toString(),
    scriptSrc: scriptUri.toString()
  });

  let lastResults: GraphResult[] = [];

  panel.webview.onDidReceiveMessage(async (message: IncomingMessage) => {
    if (message.command === 'requestSubscriptions') {
      await sendAvailableSubscriptions(panel);
      return;
    }

    if (message.command === 'lookupCidr') {
      const cidrs = message.cidr
        .split(/[,\n]/)
        .map(part => part.trim())
        .filter(Boolean);

      const requestedSubscriptions = Array.isArray(message.subscriptions)
        ? message.subscriptions.map(id => id.trim()).filter(Boolean)
        : [];

      panel.webview.postMessage({ command: 'setLoading', value: true });
      try {
        const config = vscode.workspace.getConfiguration(CONFIG_NAMESPACE);
        const token = (config.get<string>('azureGraphToken') || '').trim();
        if (!token) {
          throw new Error('Configure an Azure Resource Graph token in the Azure CIDR Analyzer settings first.');
        }

        const subscriptions = await resolveSubscriptions(token, requestedSubscriptions);
        if (!subscriptions.length) {
          throw new Error('No subscriptions available for the current token.');
        }

        panel.webview.postMessage({
          command: 'initSubscriptions',
          subscriptions: subscriptions.map(sub => ({ id: sub.id, name: sub.name }))
        });

        lastResults = [];

        for (const subscription of subscriptions) {
          panel.webview.postMessage({
            command: 'subscriptionStatus',
            subscriptionId: subscription.id,
            status: 'running'
          });
          try {
            const hits = await queryAzureForCidrs(token, cidrs, [subscription.id]);
            lastResults.push(...hits);
            panel.webview.postMessage({
              command: 'subscriptionStatus',
              subscriptionId: subscription.id,
              status: 'done',
              count: hits.length
            });
          } catch (errSub: any) {
            const msg = errSub?.message ?? String(errSub ?? 'Unknown error');
            panel.webview.postMessage({
              command: 'subscriptionStatus',
              subscriptionId: subscription.id,
              status: 'error',
              message: msg
            });
          }
        }

        const columns = collectColumns(lastResults);
        panel.webview.postMessage({
          command: 'displayResults',
          cidrs,
          results: lastResults,
          columns
        });

        const summaryText = lastResults.length
          ? `Search completed. Found ${lastResults.length} matching entr${lastResults.length === 1 ? 'y' : 'ies'}.`
          : `Search completed. No matches found for ${cidrs.join(', ')}.`;
        panel.webview.postMessage({ command: 'showInfo', message: summaryText });
      } catch (err: any) {
        const msg = err?.message ?? String(err ?? 'Unknown error');
        vscode.window.showErrorMessage(`Azure CIDR Analyzer error: ${msg}`);
        panel.webview.postMessage({ command: 'showError', message: msg });
      } finally {
        panel.webview.postMessage({ command: 'setLoading', value: false });
      }
      return;
    }

    if (message.command === 'exportCsv') {
      if (!lastResults.length) {
        vscode.window.showWarningMessage('No results to export yet. Run a search first.');
        panel.webview.postMessage({ command: 'showInfo', message: 'Run a search to export results.' });
        return;
      }

      const columns = collectColumns(lastResults);
      const header = columns.map(col => `"${col.replace(/"/g, '""')}"`).join(',');
      const csvBody = lastResults
        .map(row => columns
          .map(col => {
            const value = row[col];
            if (value === undefined || value === null) return '""';
            const str = typeof value === 'object'
              ? JSON.stringify(value)
              : String(value);
            return `"${str.replace(/"/g, '""')}"`;
          })
          .join(','))
        .join('\n');

      void exportCsv('microsoft-azure-cidr-analyzer', 'azure-cidr-results', csvBody, header + '\n');
      return;
    }
  });
}

// =========================================================================
// INTERNAL helpers
// =========================================================================
async function queryAzureForCidrs(token: string, cidrs: string[], subscriptions: string[]): Promise<GraphResult[]> {
  if (!subscriptions.length) {
    return [];
  }

  const endpoint = 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01';
  const query = buildResourceGraphQuery(cidrs);

  console.log('[AzureCIDR] Query subscriptions:', subscriptions.join(', '));
  console.log('[AzureCIDR] Query string:', query);

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      subscriptions,
      query,
      options: { resultFormat: 'objectArray' }
    })
  });

  if (!response.ok) {
    let errorText = `${response.status}`;
    try {
      const errorBody = await response.json();
      errorText = errorBody?.error?.message || JSON.stringify(errorBody);
    } catch {
      errorText = await response.text();
    }
    console.error('[AzureCIDR] Request failed:', errorText);
    throw new Error(`Azure Resource Graph request failed: ${errorText}`);
  }

  const data = await response.json();
  const rows: any[] = Array.isArray(data?.data) ? data.data : [];
  return rows as GraphResult[];
}

let cachedSubscriptions: SubscriptionInfo[] | undefined;
let cachedToken: string | undefined;

async function listSubscriptions(token: string): Promise<SubscriptionInfo[]> {
  if (cachedSubscriptions?.length && cachedToken === token) {
    return cachedSubscriptions;
  }

  const response = await fetch('https://management.azure.com/subscriptions?api-version=2020-01-01', {
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });

  if (!response.ok) {
    let detail = `${response.status}`;
    try {
      const errBody = await response.json();
      detail = errBody?.error?.message || JSON.stringify(errBody);
    } catch {
      detail = await response.text();
    }
    throw new Error(`Unable to list subscriptions: ${detail}`);
  }

  const payload = await response.json();
  const subs: SubscriptionInfo[] = Array.isArray(payload?.value)
    ? payload.value
        .map((entry: any) => ({
          id: typeof entry?.subscriptionId === 'string' ? entry.subscriptionId : '',
          name: typeof entry?.displayName === 'string' ? entry.displayName : undefined
        }))
        .filter((entry: SubscriptionInfo) => entry.id.length > 0)
    : [];

  if (!subs.length) {
    throw new Error('No subscriptions returned for the current token. Verify the token scope and permissions.');
  }

  cachedToken = token;
  cachedSubscriptions = subs;
  return subs;
}

async function resolveSubscriptions(token: string, requested: string[]): Promise<SubscriptionInfo[]> {
  const all = await listSubscriptions(token);
  if (!requested.length) {
    return all;
  }

  const byId = new Map(all.map(sub => [sub.id.toLowerCase(), sub] as const));
  const unique: SubscriptionInfo[] = [];
  const seen = new Set<string>();
  for (const raw of requested) {
    const key = raw.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    const match = byId.get(key);
    if (match) {
      unique.push(match);
    } else {
      unique.push({ id: raw });
    }
  }
  return unique;
}

async function sendAvailableSubscriptions(panel: vscode.WebviewPanel): Promise<void> {
  try {
    const config = vscode.workspace.getConfiguration(CONFIG_NAMESPACE);
    const token = (config.get<string>('azureGraphToken') || '').trim();
    if (!token) {
      panel.webview.postMessage({
        command: 'showError',
        message: 'Configure an Azure Resource Graph token in the Azure CIDR Analyzer settings to load subscriptions.'
      });
      return;
    }

    const subs = await listSubscriptions(token);
    panel.webview.postMessage({ command: 'subscriptionOptions', subscriptions: subs });
  } catch (err: any) {
    const msg = err?.message ?? String(err ?? 'Unknown error');
    vscode.window.showErrorMessage(`Failed to load Azure subscriptions: ${msg}`);
    panel.webview.postMessage({ command: 'showError', message: msg });
  }
}

function buildResourceGraphQuery(cidrs: string[]): string {
  const lower = Array.from(new Set(cidrs.map(c => c.toLowerCase()).filter(Boolean)));

  const exactMatches = lower.filter(c => !c.includes('*'));
  const wildcardMatches = lower.filter(c => c.includes('*'));

  const clauses: string[] = [];
  if (exactMatches.length) {
    const list = exactMatches
      .map(c => `'${c.replace(/'/g, "\\'")}'`)
      .join(', ');
    clauses.push(`prefixStr in~ (${list})`);
  }
  if (wildcardMatches.length) {
    const toRegex = (value: string): string => {
      const placeholder = '__WILDCARD__';
      const withPlaceholder = value.replace(/\*/g, placeholder);
      const escaped = withPlaceholder.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
      const regexBody = escaped.replace(new RegExp(placeholder, 'g'), '.*');
      const anchored = `^${regexBody}$`;
      return `'${anchored.replace(/'/g, "\\'")}'`;
    };
    const conditions = wildcardMatches
      .map(value => `prefixStr matches regex ${toRegex(value)}`)
      .join(' or ');
    clauses.push(conditions);
  }

  const filterClause = clauses.length ? `\n| where ${clauses.join(' or ')}` : '';

  return `Resources
| where type in~ ('microsoft.network/virtualnetworks', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/publicipprefixes', 'microsoft.network/ipgroups')
| extend prefixes = case(
    type =~ 'microsoft.network/virtualnetworks', properties.addressSpace.addressPrefixes,
    type =~ 'microsoft.network/virtualnetworks/subnets', coalesce(properties.addressPrefixes, pack_array(properties.addressPrefix)),
    type =~ 'microsoft.network/publicipprefixes', pack_array(properties.ipPrefix),
    type =~ 'microsoft.network/ipgroups', properties.ipAddresses,
    dynamic([])
  )
| mv-expand prefix = prefixes
| where isnotempty(prefix)
| extend prefixStr = tolower(tostring(prefix))${filterClause}
| project name, type, location, resourceGroup, subscriptionId, prefixStr, id`;
}

function collectColumns(rows: GraphResult[]): string[] {
  const cols = new Set<string>();
  for (const row of rows) {
    for (const key of Object.keys(row)) {
      cols.add(key);
    }
  }
  return Array.from(cols).sort();
}

interface WebviewContentOptions {
  nonce: string;
  cspSource: string;
  elementsSrc: string;
  commonStyleSrc: string;
  styleSrc: string;
  scriptSrc: string;
}

function showWebviewContent(opts: WebviewContentOptions): string {
  const { nonce, cspSource, elementsSrc, commonStyleSrc, styleSrc, scriptSrc } = opts;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${cspSource} https: data:; script-src 'nonce-${nonce}' ${cspSource}; style-src 'unsafe-inline' ${cspSource}; font-src ${cspSource} https: data:; connect-src ${cspSource} https:;">
  <script type="module" nonce="${nonce}" src="${elementsSrc}"></script>
  <link rel="stylesheet" href="${commonStyleSrc}" />
  <link rel="stylesheet" href="${styleSrc}" />
</head>
<body>
  <div class="layout">
    <div class="top-bar">
      <h1>Azure CIDR Analyzer</h1>
    </div>
    <div class="header flex-row section-padding">
      <vscode-form-container responsive="true">
        <div class="input-block">
          <vscode-label for="cidrInput">CIDR to search</vscode-label>
          <vscode-form-helper>
            <p>Search a single CIDR, multiple comma separated CIDRs, leave blank to list all prefixes, or use wildcards such as <code>10.10.*</code>.</p>
          </vscode-form-helper>
          <vscode-textfield id="cidrInput" placeholder="10.0.0.0/24, 10.0.1.0/24"></vscode-textfield>
        </div>
        <div class="input-block">
          <vscode-label>Subscriptions</vscode-label>
          <div id="subscriptionOptions" class="subscription-options"></div>
        </div>
        <div class="actions-row">
          <vscode-button id="searchBtn">Search</vscode-button>
          <vscode-button id="exportBtn">Export CSV</vscode-button>
        </div>
        <vscode-form-helper>
          <p>Configure the Azure Graph token under the Azure CIDR Analyzer extension settings. Choose one or more subscriptions or keep <strong>All subscriptions</strong> selected to query every subscription available to this token.</p>
        </vscode-form-helper>
        <div id="status" role="status"></div>
      </vscode-form-container>
    </div>
    <div class="middle section-padding scrollable-y">
      <div id="subscriptions"></div>
      <div id="results"></div>
    </div>
  </div>
  <script nonce="${nonce}" src="${scriptSrc}"></script>
</body>
</html>`;
}
