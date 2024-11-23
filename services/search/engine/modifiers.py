def prepare_descriptions(vulnerabilities):
    for vuln in vulnerabilities:
        seen = set()
        unique_descriptions = []
        for description in vuln.descriptions:
            clean_text = description["text"].replace("\n", " ")
            if clean_text not in seen:
                seen.add(clean_text)
                description["text"] = clean_text
                unique_descriptions.append(description)
        vuln.descriptions = unique_descriptions
    return vulnerabilities
