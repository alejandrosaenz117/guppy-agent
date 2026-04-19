// Quick test of the scrubber logic
const testCases = [
  // Key-value patterns
  'api_key="secret123"',
  'apikey : "mykey"',
  'password = "pass123"',
  'aws_secret_access_key="AKIAIOSFODNN7EXAMPLE"',
  
  // Standalone patterns
  'ghp_abc123def456ghi789jkl012mno345pqr678st',
  'AKIA0SFODNN7EXAMPLE',
  'abc123def456abc123def456abc123def456abcd',
];

testCases.forEach(test => {
  const parts = test.split(/[:=]/);
  console.log(`Input: "${test}"`);
  console.log(`Parts: [${parts.map(p => `"${p}"`).join(', ')}]`);
  console.log(`Has key-value structure: ${parts.length > 1 && parts[0].trim().length > 0}`);
  console.log('---');
});
