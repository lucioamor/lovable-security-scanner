// ============================================================
// Lovable Security Scanner — Supabase RLS Scanner
// ============================================================
//
// Non-invasive scanner that checks if Supabase RLS policies
// are properly configured on your projects' databases.
// Uses only the anon (public) key — never the service_role.
// ============================================================

export interface RLSCheckResult {
  supabaseUrl: string;
  tablesFound: string[];
  tablesWithoutRLS: string[];
  tablesWithWeakRLS: string[];
  isVulnerable: boolean;
  error?: string;
}

/**
 * Extract Supabase credentials from source code content
 */
export function extractSupabaseCredentials(content: string): {
  url: string | null;
  anonKey: string | null;
  serviceRoleKey: string | null;
} {
  // Extract URL
  const urlMatch = content.match(/https:\/\/[a-z0-9-]+\.supabase\.co/i);
  const url = urlMatch ? urlMatch[0] : null;

  // Extract anon key (JWT format)
  const anonKeyPatterns = [
    /(?:SUPABASE_PUBLISHABLE_KEY|SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE_ANON_KEY|supabaseKey|anonKey)\s*[:=]\s*['"]?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/i,
    /createClient\s*\(\s*['"][^'"]+['"]\s*,\s*['"](eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/i,
  ];

  let anonKey: string | null = null;
  for (const pattern of anonKeyPatterns) {
    const match = content.match(pattern);
    if (match) {
      anonKey = match[1];
      break;
    }
  }

  // Extract service role key (CRITICAL finding)
  const serviceRolePatterns = [
    /(?:SUPABASE_SERVICE_ROLE_KEY|service_role)\s*[:=]\s*['"]?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/i,
  ];

  let serviceRoleKey: string | null = null;
  for (const pattern of serviceRolePatterns) {
    const match = content.match(pattern);
    if (match) {
      serviceRoleKey = match[1];
      break;
    }
  }

  return { url, anonKey, serviceRoleKey };
}

/**
 * Test RLS configuration by attempting to query tables with anon key
 * This is NON-INVASIVE — only reads metadata, never modifies data
 */
export async function testRLS(supabaseUrl: string, anonKey: string): Promise<RLSCheckResult> {
  const result: RLSCheckResult = {
    supabaseUrl,
    tablesFound: [],
    tablesWithoutRLS: [],
    tablesWithWeakRLS: [],
    isVulnerable: false,
  };

  try {
    // Try to discover tables by querying common table names
    const commonTables = [
      'users', 'profiles', 'accounts', 'customers',
      'orders', 'payments', 'subscriptions',
      'posts', 'comments', 'messages',
      'events', 'speakers', 'attendees', 'registrations',
      'contacts', 'leads', 'members',
      'products', 'categories', 'tags',
      'settings', 'configurations',
      'documents', 'files', 'uploads',
      'notifications', 'logs', 'audit_log',
    ];

    for (const tableName of commonTables) {
      try {
        const response = await fetch(
          `${supabaseUrl}/rest/v1/${tableName}?select=*&limit=1`,
          {
            headers: {
              'apikey': anonKey,
              'Authorization': `Bearer ${anonKey}`,
              'Content-Type': 'application/json',
              'Prefer': 'count=exact',
            },
          }
        );

        if (response.status === 200) {
          result.tablesFound.push(tableName);
          const data = await response.json();
          const count = response.headers.get('content-range');

          // If we got data back without auth, RLS is likely missing or too permissive
          if (Array.isArray(data) && data.length > 0) {
            result.tablesWithoutRLS.push(tableName);
          } else if (count && !count.includes('0')) {
            result.tablesWithWeakRLS.push(tableName);
          }
        }
        // 404 = table doesn't exist (normal)
        // 401/403 = RLS is blocking (good!)
      } catch {
        // Network error for this table, skip
      }
    }

    result.isVulnerable = result.tablesWithoutRLS.length > 0;
  } catch (err) {
    result.error = `Erro ao testar RLS: ${(err as Error).message}`;
  }

  return result;
}
