export interface ChiasmusContext {
  mapSummary: string;
  graphSummary: string;
}

export interface ChiasmusAnalyzer {
  verify(findings: any[]): Promise<any>;
}
