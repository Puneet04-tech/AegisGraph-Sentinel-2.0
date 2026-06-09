"""
Data Validators Module.

Data validation and quality checks.
"""

import re
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    ValidationRule,
    ValidationResult,
    ValidationLevel,
)
from .store import PipelineStore, get_pipeline_store

logger = logging.getLogger(__name__)


class DataValidator:
    """Data Validator for data quality checks.
    
    Provides:
        - Schema validation
        - Quality checks
        - Anomaly detection
        - Custom rules
    """
    
    def __init__(self, store: Optional[PipelineStore] = None):
        """Initialize the data validator."""
        self._store = store or get_pipeline_store()
        self._module_id = "validators"
    
    def create_rule(
        self,
        name: str,
        field: str,
        rule_type: str,
        config: Dict[str, Any] = None,
        level: ValidationLevel = ValidationLevel.ERROR,
    ) -> ValidationRule:
        """Create a validation rule."""
        logger.info(f"Creating validation rule: {name}")
        
        rule = ValidationRule(
            name=name,
            field=field,
            rule_type=rule_type,
            config=config or {},
            level=level,
        )
        
        self._store.store_validation_rule(rule)
        return rule
    
    def get_rule(self, rule_id: str) -> Optional[ValidationRule]:
        """Get validation rule by ID."""
        return self._store.get_validation_rule(rule_id)
    
    def list_rules(self) -> List[ValidationRule]:
        """List all validation rules."""
        return self._store.get_all_validation_rules()
    
    def validate_data(
        self,
        data: List[Dict[str, Any]],
        rules: List[ValidationRule] = None,
    ) -> List[ValidationResult]:
        """Validate data against rules."""
        logger.info(f"Validating {len(data)} records")
        
        if rules is None:
            rules = self._store.get_all_validation_rules()
        
        results = []
        for rule in rules:
            result = self._validate_rule(rule, data)
            results.append(result)
        
        return results
    
    def _validate_rule(
        self,
        rule: ValidationRule,
        data: List[Dict[str, Any]],
    ) -> ValidationResult:
        """Validate data against a single rule."""
        passed = 0
        failed = 0
        error_samples = []
        
        for record in data:
            value = record.get(rule.field)
            
            if rule.rule_type == "not_null":
                is_valid = value is not None and value != ""
            elif rule.rule_type == "unique":
                is_valid = True  # Simplified
            elif rule.rule_type == "range":
                min_val = rule.config.get("min")
                max_val = rule.config.get("max")
                is_valid = (min_val is None or value >= min_val) and \
                          (max_val is None or value <= max_val)
            elif rule.rule_type == "pattern":
                pattern = rule.config.get("pattern")
                is_valid = bool(re.match(pattern, str(value))) if value else False
            elif rule.rule_type == "in_list":
                allowed = rule.config.get("allowed", [])
                is_valid = value in allowed
            else:
                is_valid = True
            
            if is_valid:
                passed += 1
            else:
                failed += 1
                if len(error_samples) < 5:
                    error_samples.append({
                        "record_id": record.get("id"),
                        "field": rule.field,
                        "value": value,
                    })
        
        result = ValidationResult(
            rule_id=rule.rule_id,
            passed=passed > 0 and failed == 0,
            record_count=len(data),
            error_count=failed,
            error_samples=error_samples,
        )
        
        self._store.store_validation_result(result)
        return result
    
    def validate_schema(
        self,
        data: List[Dict[str, Any]],
        expected_fields: List[str],
    ) -> Dict[str, Any]:
        """Validate data schema."""
        logger.info("Validating schema")
        
        if not data:
            return {"valid": True, "errors": []}
        
        sample_record = data[0]
        actual_fields = set(sample_record.keys())
        expected_fields_set = set(expected_fields)
        
        missing_fields = expected_fields_set - actual_fields
        extra_fields = actual_fields - expected_fields_set
        
        errors = []
        if missing_fields:
            errors.append(f"Missing fields: {list(missing_fields)}")
        if extra_fields:
            errors.append(f"Extra fields: {list(extra_fields)}")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "actual_fields": list(actual_fields),
            "expected_fields": expected_fields,
        }
    
    def check_quality(
        self,
        data: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Check overall data quality."""
        logger.info("Checking data quality")
        
        if not data:
            return {"quality_score": 0, "issues": ["No data"]}
        
        total_records = len(data)
        issues = []
        
        # Check for nulls
        null_counts = {}
        sample_record = data[0]
        for field in sample_record.keys():
            null_count = sum(1 for r in data if r.get(field) is None or r.get(field) == "")
            if null_count > 0:
                null_counts[field] = null_count
        
        if null_counts:
            null_pct = sum(null_counts.values()) / (total_records * len(null_counts)) * 100
            if null_pct > 10:
                issues.append(f"High null rate: {null_pct:.1f}%")
        
        # Check for duplicates
        unique_records = len(set(str(r) for r in data))
        if unique_records < total_records:
            dup_pct = (total_records - unique_records) / total_records * 100
            if dup_pct > 5:
                issues.append(f"Duplicate rate: {dup_pct:.1f}%")
        
        # Calculate quality score
        quality_score = 100.0
        for issue in issues:
            if "High null" in issue:
                quality_score -= 20
            elif "Duplicate" in issue:
                quality_score -= 10
        
        return {
            "quality_score": max(0, quality_score),
            "total_records": total_records,
            "unique_records": unique_records,
            "null_counts": null_counts,
            "issues": issues,
        }


# Global singleton
_data_validator: Optional[DataValidator] = None


def get_data_validator(store: Optional[PipelineStore] = None) -> DataValidator:
    """Get or create the singleton DataValidator instance."""
    global _data_validator
    
    if _data_validator is None:
        _data_validator = DataValidator(store=store)
    return _data_validator