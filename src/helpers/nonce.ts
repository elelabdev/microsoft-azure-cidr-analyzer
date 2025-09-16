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

// src/helpers/nonce.ts

export function getNonce(): string {
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let text = '';
  for (let i = 0; i < 32; i += 1) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}
