export interface ResponseMetadata {
  data_source: string;
  domain: string;
  disclaimer: string;
  freshness?: string;
}

export interface ToolResponse<T> {
  results: T;
  _metadata: ResponseMetadata;
}

export function generateResponseMetadata(builtAt?: string): ResponseMetadata {
  return {
    data_source: 'NIST (800-53/63/207), MITRE (ATT&CK/CWE/CAPEC), OWASP ASVS, CIS Controls, CISA ZTMM, IETF RFCs, W3C, vendor documentation',
    domain: 'iam',
    disclaimer: 'IAM guidance for threat modeling, compliance, and architecture review. This is not legal advice. Verify requirements against authoritative sources before making security decisions.',
    freshness: builtAt,
  };
}
