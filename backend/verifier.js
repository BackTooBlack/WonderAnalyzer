/**
 * Hash Verification Module
 * Verifies mod hashes against Modrinth API for known legitimate mods
 */

const https = require('https');

/**
 * Verify a SHA-1 hash against the Modrinth API
 */
function verifyHash(hash) {
  return new Promise((resolve) => {
    const options = {
      hostname: 'api.modrinth.com',
      path: `/v2/version_file/${hash}`,
      method: 'GET',
      headers: {
        'User-Agent': 'WonderAnalyzer/1.0',
        'Accept': 'application/json'
      },
      timeout: 8000
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode === 200) {
            const result = JSON.parse(data);
            resolve({
              verified: true,
              source: 'Modrinth',
              project: result.project?.title || result.project_id || 'Unknown',
              version: result.version_number || 'Unknown',
              loaders: result.loaders || [],
              gameVersions: result.game_versions || []
            });
          } else {
            // Not found on Modrinth, try megabase as backup
            verifyAgainstMegabase(hash).then(resolve).catch(() => {
              resolve({ verified: false, source: null });
            });
          }
        } catch (e) {
          resolve({ verified: false, source: null });
        }
      });
    });

    req.on('error', () => {
      resolve({ verified: false, source: null });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ verified: false, source: null });
    });

    req.end();
  });
}

/**
 * Fallback verification against Megabase API
 */
function verifyAgainstMegabase(hash) {
  return new Promise((resolve) => {
    const options = {
      hostname: 'megabase.vercel.app',
      path: `/api/query?hash=${hash}`,
      method: 'GET',
      headers: {
        'User-Agent': 'WonderAnalyzer/1.0',
        'Accept': 'application/json'
      },
      timeout: 8000
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode === 200) {
            const result = JSON.parse(data);
            if (result.found || result.project) {
              resolve({
                verified: true,
                source: 'Megabase',
                project: result.project || 'Unknown',
                version: result.version || 'Unknown'
              });
            } else {
              resolve({ verified: false, source: null });
            }
          } else {
            resolve({ verified: false, source: null });
          }
        } catch (e) {
          resolve({ verified: false, source: null });
        }
      });
    });

    req.on('error', () => resolve({ verified: false, source: null }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ verified: false, source: null });
    });

    req.end();
  });
}

module.exports = { verifyHash, verifyAgainstMegabase };
