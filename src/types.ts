export type HeaderLine = {
  name: string;
  value: string;
};

export type HeaderInput = HeaderLine[] | Record<string, string | string[] | undefined>;

export type AuthenticationMethodResult = {
  method: string;
  result: string;
  properties: Record<string, string>;
};

export type AuthenticationResultsHeader = {
  raw: string;
  authservId: string;
  trusted: boolean;
  methods: AuthenticationMethodResult[];
};

export type SignalSeverity = "info" | "low" | "medium" | "high";

export type Signal = {
  key: string;
  severity: SignalSeverity;
  message: string;
  data?: Record<string, unknown>;
};

export type MessageMetrics = {
  fromDomain: string | null;
  messageIdDomain: string | null;
  messageIdDomainMatchesFromDomain: boolean | null;
  authenticationResults: AuthenticationResultsHeader[];
};

export type AnalyzeOptions = {
  trustedAuthservIds?: string[];
};

export type AnalyzeInput = {
  headers: HeaderInput;
  options?: AnalyzeOptions;
};

export type AnalyzeResult = {
  metrics: MessageMetrics;
  signals: Signal[];
};

