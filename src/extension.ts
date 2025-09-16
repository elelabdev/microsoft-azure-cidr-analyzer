/*****************************************************************************
 *   Extension:   Microsoft Azure CIDRs Analyzer                             *
 *   Author:      elelabdev                                                  *
 *   Description: Query right from Visual Studio Code all Microsoft Azure    *
 *                subscriptions and search for specific CIDRs in use.        *
 *   Github:      https://github.com/elelabdev/microsoft-azure-cidr-analyzer *
 *                                                                           *
 *   Icon Author: elelab                                                     *
 *                                                                           *
 *   Licensed under the MIT License. See LICENSE file in the project         *
 *   root for details.                                                       *
 ****************************************************************************/

// src/extension.ts

import * as vscode from 'vscode';
import { openAzureCidrAnalyzer } from './modules/azureCidrAnalyzer';

const AZURE_CIDR_COMMAND = 'azureCidrAnalyzer.open';

export function activate(context: vscode.ExtensionContext): void {
  const disposable = vscode.commands.registerCommand(AZURE_CIDR_COMMAND, () => {
    openAzureCidrAnalyzer(context);
  });

  context.subscriptions.push(disposable);
}

export function deactivate(): void {
  // Nothing to clean up command registration is disposed automatically.
}
