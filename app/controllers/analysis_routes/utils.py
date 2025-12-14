def calculate_malscore(parsed_results: dict, ai_analysis: dict) -> float:
    """
    Calculate a simple malware score for demonstration.
    """
    score = 0.0

    if "signatures" in parsed_results.get("sections", {}):
        sigs = parsed_results["sections"]["signatures"]
        if isinstance(sigs, dict) and "signatures" in sigs:
            score += len(sigs["signatures"]) * 0.5

    if "results" in ai_analysis and "final_synthesis" in ai_analysis["results"]:
        synthesis = ai_analysis["results"]["final_synthesis"]
        if isinstance(synthesis, str):
            if "malicious" in synthesis.lower():
                score += 3.0
            if "suspicious" in synthesis.lower():
                score += 2.0

    return min(10.0, score)
