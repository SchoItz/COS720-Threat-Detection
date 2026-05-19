

import json
import os
from typing import Dict, List, Any


RISK_MULTIPLIERS = {
    "HIGH": 2.0,    
    "MEDIUM": 1.2,  
    "LOW": 0.8,     
}

RISK_COLOURS = {
    "HIGH": "#dc3545",
    "MEDIUM": "#fd7e14",
    "LOW": "#ffc107",
    "NORMAL": "#28a745",
}


FEATURE_EXPLANATIONS = {
    "total_files_burned": {
        "HIGH": (
            "This employee burned an abnormal number of files to USB drives, CDs, etc. "
            "This is a strong  indicator of data exfiltration"
            
        ),
        "MEDIUM": (
            "This employee burned more files than most normal employees. "
            "This might be authorized but should be monitored."
        ),
        "LOW": (
            "Slightly deviation from normal "
            "file burning activity detected."
            
        ),
    },
    "burned_from_other": {
        "HIGH": (
            "A lot of file were burned from non-standard locations. "
            "This suggests the employee may have been deliberately bypassing "
            "standard data handling controls."
        ),
        "MEDIUM": (
            "Some files burned from non-standard locations. "
            "Could indicate attempts to "
            "avoid normal monitoring channels."
        ),
        "LOW": "Minor deviation from standard.",
    },
    "num_printed_pages_off_hours": {
        "HIGH": (
            "A lot of documents were printed outside of normal working hours "
            "After-hours printing of sensitive documents "
            "is a recognised attack pattern"
        ),
        "MEDIUM": (
            "Some documents were printed outside of normal working hours. "
            "This could indicate attempts to distribute sensitive information after hours."
        ),
        "LOW":( 
            "A few documents where printed"
            "outside of normal working hours."),
    },
    "total_printed_pages": {
        "HIGH": (
            "Printed an abnormal number of pages today."
            "Bulk printing before resignation"
            "is a common tactic used by departing insiders."
        ),
        "MEDIUM": (
            "Printed a lot of pages today. "
            "This may be legitimate but combined"
            "with other indicators, this raises concern."
        ),
        "LOW": "Printed slightly more than the average employee today.",
    },
    "num_entries": {
        "HIGH": (
            "An abnormal number of building entries. "
            "This may indicate unauthorised access attempts or "
            "unusual movement patterns within the facility."
        ),
        "MEDIUM": "Above-average number of building entries today.",
        "LOW": "Slightly elevated building access frequency.",
    },
    "late_exit_flag": {
        "HIGH": (
            "Staying significantly beyond normal working "
            "hours may coincide with after-hours system access or "
            "physical document handling."
        ),
        "MEDIUM": "The employee stayed later than usual today.",
        "LOW": "Slightly later-than-normal exit recorded.",
    },
    "entry_during_weekend": {
        "HIGH": (
            "The employee accessed the building on a weekend. "
            "Legitimate access will have permission. "
            "Weekend access is a recognised physical insider threat attack pattern."
        ),
        "MEDIUM": "Weekend building access recorded.",
        "LOW": "A weekend building entry was recorded.",
    },
    "trip_day_number": {
        "HIGH": (
            "Lots of travel days, "
            "is associated with potential exposure to "
            "foreign intelligence recruitment attempts."
        ),
        "MEDIUM": "Longer-than-average business trip recorded.",
        "LOW": "Slightly extended travel duration noted.",
    },
    "hostility_country_level": {
        "HIGH": (
            "The employee has travelled to a country classified as high-risk."
            " This does not indicate guilt, "
            " but it warrants additional review per security policy."
        ),
        "MEDIUM": "Travel to a country with moderate security risk.",
        "LOW": "Travel to a country with slightly elevated risk.",
    },
    "has_criminal_record": {
        "HIGH": (
            "A criminal record is on file for this employee. "
            "This is a contextual background flag and does not imply current misconduct, "
            "but it is a recognised risk factor under insider threat frameworks."
        ),
        "MEDIUM": "A criminal record flag is present for this employee.",
        "LOW": "A criminal record flag is present for this employee.",
    },
    "employee_seniority_years": {
        "HIGH": (
            "This is a senior, long-tenured employee. "
            "Senior employees often have more knowledge of and access to sensitive systems, "
            "making their actions potentially more impactful."
        ),
        "MEDIUM": "Mid-to-senior level employee with significant system access.",
        "LOW": "Employee tenure noted as a contextual factor.",
    },
}


class Explainer:
  
    def __init__(self, metadata_path: str = None):
        self.thresholds: Dict[str, Dict] = {}
        self.feature_importances: Dict[str, float] = {}
        self.numeric_features: List[str] = []
        self.categorical_features: List[str] = []

        if metadata_path and os.path.exists(metadata_path):
            with open(metadata_path, "r") as f:
                meta = json.load(f)
                self.thresholds = meta.get("thresholds", {})
                self.feature_importances = meta.get("feature_importances", {})
                self.numeric_features = meta.get("numeric_features", [])
                self.categorical_features = meta.get("categorical_features", [])

    def get_risk_level(self, feature: str, value: float) -> str:
        
        if feature not in self.thresholds:
            return "NORMAL"

        thresh = self.thresholds[feature]
        baseline = thresh.get("normal_75th", 0)

        if baseline == 0:
            return "NORMAL"

        ratio = value / baseline

        if ratio >= RISK_MULTIPLIERS["HIGH"]:
            return "HIGH"
        elif ratio >= RISK_MULTIPLIERS["MEDIUM"]:
            return "MEDIUM"
        elif ratio >= RISK_MULTIPLIERS["LOW"]:
            return "LOW"
        else:
            return "NORMAL"

    def get_risk_indicators(self, instance: dict) -> List[Dict[str, Any]]:
       
        indicators = []

        for feature in self.numeric_features:
            if feature not in instance:
                continue
            try:
                value = float(instance[feature])
            except (ValueError, TypeError):
                continue

            risk_level = self.get_risk_level(feature, value)
            if risk_level == "NORMAL":
                continue

            thresh = self.thresholds.get(feature, {})
            baseline = thresh.get("normal_75th", 0)

            from preprocess import FEATURE_LABELS
            label = FEATURE_LABELS.get(feature, feature.replace("_", " ").title())

            explanation_map = FEATURE_EXPLANATIONS.get(feature, {})
            explanation = explanation_map.get(
                risk_level,
                f"({value:.1f}) is elevated relative to normal "
                f"behaviour (typical threshold: {baseline:.1f})."
            )

            importance = self.feature_importances.get(feature, 0.0)

            indicators.append({
                "feature": feature,
                "label": label,
                "value": round(value, 2),
                "baseline": round(baseline, 2),
                "risk_level": risk_level,
                "colour": RISK_COLOURS[risk_level],
                "importance": round(importance * 100, 2),
                "explanation": explanation,
            })

        risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        indicators.sort(
            key=lambda x: (risk_order.get(x["risk_level"], 3), -x["importance"])
        )
        return indicators

    def generate_manager_explanation(
        self, prediction: int, probability: float, indicators: List[Dict]
    ) -> str:
       
        confidence_pct = round(probability * 100, 1)
        label = "Malicious Insider Activity" if prediction == 1 else "Normal Behaviour"

        if prediction == 0:
            return (
                f"The AI system has classified this employee's activity as NORMAL "
                f"({confidence_pct}% confidence).  No significant "
                f"risk indicators were detected that would suggest insider threat activity. "
                f"No immediate action is required."
            )

        
        high_risks = [i for i in indicators if i["risk_level"] == "HIGH"]
        medium_risks = [i for i in indicators if i["risk_level"] == "MEDIUM"]

        explanation = (
            f"The AI system has flagged this employee's activity as potentially "
            f"MALICIOUS ({confidence_pct}% confidence). This means the system has "
            f"detected a combination of behavioural patterns that are significantly "
            f"different from what is considered normal for employees in this organisation.\n\n"
        )

        if high_risks:
            explanation += "KEY CONCERNS (High Risk):\n"
            for ind in high_risks[:3]:
                explanation += f"• {ind['label']}: {ind['explanation']}\n\n"

        if medium_risks:
            explanation += "ADDITIONAL CONCERNS (Medium Risk):\n"
            for ind in medium_risks[:2]:
                explanation += f"• {ind['label']}: {ind['explanation']}\n\n"

        explanation += (
            "IMPORTANT NOTICE:This is a generated explanation "
            "and should be treated as an alert for further investigation"
            "and not used as proof of wrongdoing. The employee should be investigated "
            "before action is taken. "
        )

        return explanation

    def get_global_feature_importance(self, top_n: int = 10) -> List[Dict]:
        from preprocess import FEATURE_LABELS
        sorted_features = sorted(
            self.feature_importances.items(), key=lambda x: x[1], reverse=True
        )
        result = []
        for feat, importance in sorted_features[:top_n]:
            label = FEATURE_LABELS.get(feat, feat.replace("_", " ").title())
            result.append({
                "feature": feat,
                "label": label,
                "importance": round(importance * 100, 2),
                "bar_width": round(importance * 100, 2),
            })
        return result

    def explain_prediction(
        self, instance: dict, prediction: int, probability: float
    ) -> Dict[str, Any]:
        indicators = self.get_risk_indicators(instance)
        manager_explanation = self.generate_manager_explanation(
            prediction, probability, indicators
        )
        global_importance = self.get_global_feature_importance()

        return {
            "prediction": prediction,
            "prediction_label": "Malicious" if prediction == 1 else "Normal",
            "probability": round(probability, 4),
            "confidence_pct": round(probability * 100, 1),
            "risk_indicators": indicators,
            "manager_explanation": manager_explanation,
            "global_feature_importance": global_importance,
            "high_risk_count": len([i for i in indicators if i["risk_level"] == "HIGH"]),
            "medium_risk_count": len([i for i in indicators if i["risk_level"] == "MEDIUM"]),
            "low_risk_count": len([i for i in indicators if i["risk_level"] == "LOW"]),
        }
