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

// media/module-azurecidranalyzer/main.js

// Suppress noisy ResizeObserver loop errors in the webview console
window.addEventListener('error', (event) => {
  if (event.message?.includes('ResizeObserver loop completed with undelivered notifications')) {
    event.preventDefault();
  }
});

document.addEventListener('DOMContentLoaded', () => {
  const vscode = acquireVsCodeApi();
  const cidrInput = document.getElementById('cidrInput');
  const searchBtn = document.getElementById('searchBtn');
  const exportBtn = document.getElementById('exportBtn');
  const subscriptionOptionsDiv = document.getElementById('subscriptionOptions');
  const subscriptionsProgressDiv = document.getElementById('subscriptions');
  const resultsDiv = document.getElementById('results');
  const statusEl = document.getElementById('status');

  if (!cidrInput || !searchBtn || !exportBtn || !subscriptionOptionsDiv || !subscriptionsProgressDiv || !resultsDiv || !statusEl) {
    console.error('Azure CIDR Analyzer: missing DOM elements');
    return;
  }

  const subscriptionState = {
    options: [],
    selected: new Set()
  };

  exportBtn.disabled = true;

  const setStatus = (message, kind = 'info') => {
    statusEl.textContent = message || '';
    statusEl.className = kind ? kind : '';
  };

  const setLoading = (value) => {
    if (value) {
      searchBtn.disabled = true;
      exportBtn.disabled = true;
      setStatus('Searching Azure Resource Graph…', 'loading');
    } else if (!statusEl.textContent) {
      searchBtn.disabled = false;
      setStatus('', '');
    } else {
      searchBtn.disabled = false;
    }
  };

  const renderEmpty = (message) => {
    resultsDiv.innerHTML = '';
    const p = document.createElement('p');
    p.className = 'empty-state';
    p.textContent = message;
    resultsDiv.appendChild(p);
  };

  const resetSubscriptionsView = () => {
    subscriptionsProgressDiv.innerHTML = '';
  };

  const ensureAllCheckbox = () => {
    const allCheckbox = subscriptionOptionsDiv.querySelector('input[data-id="__all__"]');
    if (!allCheckbox) return;
    allCheckbox.checked = subscriptionState.selected.size === 0;
  };

  const renderSubscriptionOptions = (options) => {
    subscriptionState.options = options;
    subscriptionState.selected.clear();
    subscriptionOptionsDiv.innerHTML = '';

    const buildCheckbox = (labelText, value, checked = false, disabled = false) => {
      const wrapper = document.createElement('label');
      wrapper.className = 'subscription-option';

      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.dataset.id = value;
      checkbox.checked = checked;
      checkbox.disabled = disabled;

      const label = document.createElement('span');
      label.textContent = labelText;

      wrapper.append(checkbox, label);
      return { wrapper, checkbox };
    };

    const allEntry = buildCheckbox('All subscriptions', '__all__', true, options.length === 0);
    allEntry.checkbox.addEventListener('change', () => {
      if (allEntry.checkbox.checked) {
        subscriptionState.selected.clear();
        subscriptionOptionsDiv.querySelectorAll('input[type="checkbox"]').forEach(cb => {
          if (cb.dataset.id && cb.dataset.id !== '__all__') {
            cb.checked = false;
          }
        });
      } else if (subscriptionState.selected.size === 0) {
        allEntry.checkbox.checked = true;
      }
    });
    subscriptionOptionsDiv.appendChild(allEntry.wrapper);

    options.forEach(option => {
      const label = option.name ? `${option.name} (${option.id})` : option.id;
      const { wrapper, checkbox } = buildCheckbox(label, option.id, false, false);
      checkbox.addEventListener('change', () => {
        if (checkbox.checked) {
          subscriptionState.selected.add(option.id);
          allEntry.checkbox.checked = false;
        } else {
          subscriptionState.selected.delete(option.id);
          if (subscriptionState.selected.size === 0) {
            allEntry.checkbox.checked = true;
          }
        }
      });
      subscriptionOptionsDiv.appendChild(wrapper);
    });

    ensureAllCheckbox();
  };

  const createSubscriptionProgressItem = (subscription) => {
    const wrapper = document.createElement('div');
    wrapper.className = 'subscription-item';
    wrapper.dataset.id = subscription.id;

    const icon = document.createElement('span');
    icon.className = 'status-icon loading';

    const label = document.createElement('span');
    label.className = 'subscription-label';
    label.textContent = subscription.name
      ? `${subscription.name} (${subscription.id})`
      : subscription.id;

    const note = document.createElement('span');
    note.className = 'subscription-note';
    note.textContent = 'Pending…';

    wrapper.append(icon, label, note);
    subscriptionsProgressDiv.appendChild(wrapper);
  };

  const updateSubscriptionStatus = (subscriptionId, status, detail) => {
    const item = subscriptionsProgressDiv.querySelector(`[data-id="${subscriptionId}"]`);
    if (!item) {
      return;
    }
    const icon = item.querySelector('.status-icon');
    const note = item.querySelector('.subscription-note');
    icon.classList.remove('loading', 'success', 'error');

    switch (status) {
      case 'running':
        icon.classList.add('loading');
        note.textContent = 'Searching…';
        break;
      case 'done':
        icon.classList.add('success');
        note.textContent = `${detail?.count ?? 0} match${(detail?.count ?? 0) === 1 ? '' : 'es'}`;
        break;
      case 'error':
        icon.classList.add('error');
        note.textContent = detail?.message ? `Error: ${detail.message}` : 'Error';
        break;
      default:
        note.textContent = '';
        break;
    }
  };

  const renderResults = (results, cidrs, columns) => {
    const joinedCidrs = Array.isArray(cidrs) ? cidrs.join(', ') : '';

    if (!Array.isArray(results) || results.length === 0) {
      renderEmpty(`No results for ${joinedCidrs || 'your query'}.`);
      exportBtn.disabled = true;
      return;
    }

    resultsDiv.innerHTML = '';

    const table = document.createElement('vscode-table');
    table.zebra = true;
    table['bordered-rows'] = true;

    const header = document.createElement('vscode-table-header');
    header.slot = 'header';
    const safeColumns = Array.isArray(columns) && columns.length ? columns : Object.keys(results[0] || {});
    safeColumns.forEach((col) => {
      const cell = document.createElement('vscode-table-header-cell');
      cell.textContent = col;
      header.appendChild(cell);
    });
    table.appendChild(header);

    const body = document.createElement('vscode-table-body');
    body.slot = 'body';

    results.forEach((row) => {
      const tr = document.createElement('vscode-table-row');
      safeColumns.forEach((col) => {
        const td = document.createElement('vscode-table-cell');
        const value = row ? row[col] : undefined;
        if (value === null || value === undefined) {
          td.textContent = '';
        } else if (typeof value === 'object') {
          td.textContent = JSON.stringify(value);
        } else {
          td.textContent = String(value);
        }
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });

    table.appendChild(body);
    resultsDiv.appendChild(table);
    exportBtn.disabled = false;
  };

  searchBtn.addEventListener('click', () => {
    const cidr = cidrInput.value.trim();
    resetSubscriptionsView();
    resultsDiv.innerHTML = '';
    exportBtn.disabled = true;

    const selectedIds = Array.from(subscriptionState.selected);
    ensureAllCheckbox();

    vscode.postMessage({
      command: 'lookupCidr',
      cidr,
      subscriptions: selectedIds.length ? selectedIds : undefined
    });
  });

  exportBtn.addEventListener('click', () => {
    vscode.postMessage({ command: 'exportCsv' });
  });

  // Request subscription options on load
  vscode.postMessage({ command: 'requestSubscriptions' });

  window.addEventListener('message', (event) => {
    const data = event.data;
    if (!data) {
      return;
    }

    switch (data.command) {
      case 'setLoading':
        setLoading(!!data.value);
        break;
      case 'subscriptionOptions':
        renderSubscriptionOptions(data.subscriptions || []);
        break;
      case 'initSubscriptions':
        resetSubscriptionsView();
        if (Array.isArray(data.subscriptions)) {
          data.subscriptions.forEach(createSubscriptionProgressItem);
        }
        break;
      case 'subscriptionStatus':
        updateSubscriptionStatus(data.subscriptionId, data.status, { count: data.count, message: data.message });
        break;
      case 'displayResults':
        renderResults(data.results, data.cidrs, data.columns);
        setStatus(
          `Found ${data.results.length} entr${data.results.length === 1 ? 'y' : 'ies'} for ${Array.isArray(data.cidrs) ? data.cidrs.join(', ') : 'your query'}.`,
          data.results.length ? 'info' : 'warning'
        );
        break;
      case 'showError':
        setStatus(data.message || 'Unexpected error.', 'error');
        exportBtn.disabled = true;
        break;
      case 'showInfo':
        setStatus(data.message || '', 'info');
        if (data.message?.includes('No matches')) {
          renderEmpty(data.message);
        }
        break;
      default:
        break;
    }
  });
});
