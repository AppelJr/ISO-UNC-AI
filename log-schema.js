{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "AI System Validator Audit Manifest Schema",
  "type": "object",
  "required": ["timestamp", "manifest"],
  "properties": {
    "timestamp": {
      "type": "string",
      "format": "date-time",
      "description": "UTC timestamp when manifest was generated"
    },
    "host": {
      "type": "string",
      "description": "Hostname or identifier of analysis machine (optional)"
    },
    "collector": {
      "type": "string",
      "description": "Name of the person or system that collected artifacts"
    },
    "manifest": {
      "type": "array",
      "description": "List of artifact entries",
      "items": {
        "type": "object",
        "required": ["path", "sha256", "size"],
        "properties": {
          "path": { "type": "string", "description": "Relative path or filename" },
          "sha256": { "type": "string", "pattern": "^[a-fA-F0-9]{64}$" },
          "size": { "type": "integer", "minimum": 0 },
          "suspicious_patterns": {
            "type": "array",
            "items": { "type": "string" },
            "description": "List of pattern names or regex strings matched"
          },
          "notes": { "type": "string" }
        }
      }
    },
    "summary": {
      "type": "object",
      "properties": {
        "total_artifacts": { "type": "integer" },
        "suspicious_count": { "type": "integer" },
        "max_score": { "type": "number" },
        "min_score": { "type": "number" }
      }
    }
  }
}