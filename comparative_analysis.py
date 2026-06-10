import argparse
from datetime import datetime
from html import escape
import json
from pathlib import Path

from expert.compare import detect_join_type
from expert.compare import get_filter_names
from expert.compare import get_path
from expert.compare import share_names


STATUS_ACTIVE = "ACTIF"
STATUS_ELIMINATED = "ÉLIMINÉE"
STATUS_HYPOTHESIS = "HYPOTHÈSE"

CONFIDENCE_CONFIRMED = "CONFIRMÉ"
CONFIDENCE_PROBABLE = "PROBABLE"
CONFIDENCE_LOW = "FAIBLE"

AUTH_FAILURE_MARKERS = (
    "mot de passe invalide",
    "mot de passe incorrect",
    "informations d'identification n'ont pas fonctionné",
    "erreur 86",
    "erreur 1326",
    "system error 86",
    "system error 1326",
    "invalid password",
    "bad password",
    "credentials did not work",
    "logon failure",
)


def load_snapshot(filename):
    with open(filename, "r", encoding="utf-8") as handle:
        return json.load(handle)


def flatten_strings(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from flatten_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from flatten_strings(item)
    elif value is not None:
        yield str(value)


def contains_any_text(value, markers):
    haystack = "\n".join(flatten_strings(value)).lower()
    return any(marker in haystack for marker in markers)


def machine_name(snapshot):
    return (
        get_path(snapshot, "system.hostname")
        or get_path(snapshot, "metadata.target")
        or get_path(snapshot, "remote_tests.target")
        or "machine inconnue"
    )


def target_id(snapshot):
    remote = snapshot.get("remote_tests") or {}
    return (
        remote.get("target"),
        remote.get("resolved_name"),
    )


def remote_shares(snapshot):
    return share_names(get_path(snapshot, "remote_tests.accessible_smb_shares"))


def bool_value(snapshot, path):
    return get_path(snapshot, path) is True


def add_finding(
    findings,
    case,
    title,
    evidence,
    cause,
    remediation=None,
    level="INFO",
    status=STATUS_HYPOTHESIS,
    confidence=CONFIDENCE_PROBABLE,
    relevance_score=50,
    howto=None,
):
    findings.append({
        "case": case,
        "title": title,
        "level": level,
        "status": status,
        "confidence": confidence,
        "relevance_score": relevance_score,
        "evidence": evidence,
        "cause": cause,
        "remediation": remediation,
        "howto": howto,
    })


def add_eliminated(
    findings,
    case,
    title,
    evidence,
    cause,
    relevance_score=80,
):
    add_finding(
        findings,
        case=case,
        title=title,
        level="INFO",
        status=STATUS_ELIMINATED,
        confidence=CONFIDENCE_CONFIRMED,
        relevance_score=relevance_score,
        evidence=evidence,
        cause=cause,
    )


def compare_set(label, left_name, right_name, left_values, right_values):
    left_set = set(left_values or [])
    right_set = set(right_values or [])

    if left_set == right_set:
        return None

    return [
        f"{label} {left_name} : {', '.join(sorted(left_set)) or 'aucun'}",
        f"{label} {right_name} : {', '.join(sorted(right_set)) or 'aucun'}",
    ]


def compare_remote_diagnostics(working_snapshot, failing_snapshot, lang="fr"):
    findings = []
    working_name = machine_name(working_snapshot)
    failing_name = machine_name(failing_snapshot)
    working_target = target_id(working_snapshot)
    failing_target = target_id(failing_snapshot)
    target_name = (
        working_target[1]
        or failing_target[1]
        or working_target[0]
        or failing_target[0]
        or "CIBLE"
    )
    target_alias = (
        target_name.split("-", 1)[1]
        if target_name.upper().startswith("SCCF-") and "-" in target_name
        else None
    )
    target_lookup = (
        f"{target_name} ou {target_alias}"
        if target_alias and target_alias != target_name
        else target_name
    )
    target_delete_commands = (
        f"cmdkey /delete:{target_name}\n"
        f"cmdkey /delete:{target_alias}"
        if target_alias and target_alias != target_name
        else f"cmdkey /delete:{target_name}"
    )
    target_share_paths = (
        f"\\\\{target_name}\\share\n\\\\{target_alias}\\share"
        if target_alias and target_alias != target_name
        else f"\\\\{target_name}\\share"
    )
    working_remote = working_snapshot.get("remote_tests") or {}
    failing_remote = failing_snapshot.get("remote_tests") or {}
    working_shares = remote_shares(working_snapshot)
    failing_shares = remote_shares(failing_snapshot)
    auth_failure = contains_any_text(failing_snapshot, AUTH_FAILURE_MARKERS)

    if working_target[0] and failing_target[0] and working_target[0] != failing_target[0]:
        add_finding(
            findings,
            case="REMOTE_TARGET_MISMATCH",
            title="Les deux diagnostics ne ciblent pas la même adresse",
            level="WARN",
            status=STATUS_ACTIVE,
            confidence=CONFIDENCE_CONFIRMED,
            relevance_score=100,
            evidence=[
                f"{working_name} cible {working_target[0]}",
                f"{failing_name} cible {failing_target[0]}",
            ],
            cause=(
                "La comparaison Remote ↔ Remote n'est fiable que si les deux "
                "diagnostics interrogent la même cible."
            ),
            remediation="Relancer les deux diagnostics vers la même adresse IP cible.",
        )
        return sorted_findings(findings)

    if bool_value(working_snapshot, "remote_tests.ping_target") and bool_value(failing_snapshot, "remote_tests.ping_target"):
        add_eliminated(
            findings,
            case="CAUSE-ELIMINATED-TARGET-UNREACHABLE",
            title="Cible injoignable éliminée",
            relevance_score=80,
            evidence=[
                f"{working_name} : ping cible OK",
                f"{failing_name} : ping cible OK",
            ],
            cause="La cible répond depuis les deux postes clients.",
        )

    if bool_value(working_snapshot, "remote_tests.tcp_445") and bool_value(failing_snapshot, "remote_tests.tcp_445"):
        add_eliminated(
            findings,
            case="CAUSE-ELIMINATED-SMB-PORT-BLOCKED",
            title="Blocage TCP 445 éliminé",
            relevance_score=95,
            evidence=[
                f"{working_name} : TCP 445 ouvert",
                f"{failing_name} : TCP 445 ouvert",
            ],
            cause=(
                "Le transport SMB est joignable depuis les deux postes. "
                "Le problème restant est probablement au-dessus du transport : "
                "identité, droits, session SMB ou négociation."
            ),
        )

    if working_shares and not failing_shares and bool_value(failing_snapshot, "remote_tests.tcp_445"):
        add_finding(
            findings,
            case="SMB_ACCESS_DIFFERS_BY_CLIENT",
            title="Les partages SMB sont accessibles depuis un client mais pas l'autre",
            level="WARN",
            status=STATUS_HYPOTHESIS,
            confidence=CONFIDENCE_PROBABLE,
            relevance_score=95,
            evidence=[
                f"{working_name} : partages visibles = {', '.join(working_shares)}",
                f"{failing_name} : aucun partage exploitable via le diagnostic remote",
                f"{failing_name} : TCP 445 ouvert",
            ],
            cause=(
                "La cible SMB semble fonctionner, mais l'accès dépend du poste client. "
                "Les causes probables sont les identifiants mis en cache, le compte utilisé, "
                "le format du compte, ou une différence de contexte AzureAD/domaine/local."
            ),
            remediation=(
                "Sur le poste en échec : exécuter net use * /delete /y, vérifier le "
                "Gestionnaire d'identification Windows, puis retester avec un compte explicite."
            ),
        )

        add_eliminated(
            findings,
            case="CAUSE-ELIMINATED-SHARE-NOT-PUBLISHED",
            title="Partage non publié côté cible éliminé",
            relevance_score=90,
            evidence=[
                f"{working_name} voit au moins un partage : {', '.join(working_shares)}",
            ],
            cause=(
                "Au moins un autre client voit les partages de la cible. "
                "La cible ne peut donc pas être considérée comme totalement muette côté SMB."
            ),
        )

    if auth_failure:
        add_finding(
            findings,
            case="SMB_AUTH_DIFFERS_BY_CLIENT",
            title="Échec d'authentification SMB spécifique au client",
            level="WARN",
            status=STATUS_HYPOTHESIS,
            confidence=CONFIDENCE_PROBABLE,
            relevance_score=98,
            evidence=[
                f"{failing_name} contient un indice de mot de passe invalide, erreur 86/1326 ou échec d'identifiants",
                f"{working_name} sert de point de comparaison fonctionnel",
            ],
            cause=(
                "Le problème ressemble davantage à une identité ou une session SMB côté client "
                "qu'à une panne réseau ou serveur."
            ),
            remediation=(
                "Comparer whoami, whoami /upn, le compte SMB recommandé, les entrées du "
                "Gestionnaire d'identification et les sessions net use sur les deux postes. "
                f"Si une entrée mémorisée existe pour {target_name}, la supprimer avec "
                f"cmdkey /delete:{target_name}, puis vider les sessions SMB avec "
                "net use * /delete /y."
            ),
            howto=[
                ("CAUSE PROBABLE", "Ancien mot de passe mémorisé."),
                (
                    "POURQUOI",
                    f"La cible fonctionne depuis {working_name}, mais pas depuis {failing_name}.",
                ),
                (
                    "COMMENT LE VÉRIFIER",
                    f"cmdkey /list\n\nRechercher une entrée pour :\n{target_lookup}",
                ),
                (
                    "COMMENT LE CORRIGER",
                    f"{target_delete_commands}\n\npuis\n\nnet use * /delete /y",
                ),
                (
                    "COMMENT VALIDER",
                    f"Tenter :\n{target_share_paths}\n\nLe partage doit s'ouvrir sans erreur.",
                ),
            ],
        )

    working_join = detect_join_type(working_snapshot)
    failing_join = detect_join_type(failing_snapshot)

    if working_join != failing_join:
        add_finding(
            findings,
            case="IDENTITY_CONTEXT_MISMATCH",
            title="Contexte d'identité différent entre les deux clients",
            level="INFO",
            status=STATUS_HYPOTHESIS,
            confidence=CONFIDENCE_PROBABLE,
            relevance_score=78 if auth_failure or working_shares != failing_shares else 55,
            evidence=[
                f"{working_name} : {working_join}",
                f"{failing_name} : {failing_join}",
            ],
            cause=(
                "Windows peut présenter un même utilisateur sous des formes différentes "
                "selon AzureAD, domaine, compte local ou UPN. Cette différence peut changer "
                "la négociation SMB."
            ),
            remediation="Comparer whoami, whoami /upn et le compte réellement envoyé au serveur SMB.",
        )

    filter_evidence = compare_set(
        "Filtres",
        working_name,
        failing_name,
        get_filter_names(working_snapshot),
        get_filter_names(failing_snapshot),
    )

    if filter_evidence:
        add_finding(
            findings,
            case="CLIENT_FILTERS_DIFFER",
            title="Filtres système différents entre les clients",
            level="INFO",
            status=STATUS_HYPOTHESIS,
            confidence=CONFIDENCE_LOW,
            relevance_score=45,
            evidence=filter_evidence,
            cause=(
                "Des filtres antivirus, EDR, chiffrement ou synchronisation peuvent modifier "
                "le comportement SMB côté client. Pertinence faible sans autre indice."
            ),
            remediation="Vérifier seulement si les hypothèses d'identité et de credentials sont éliminées.",
        )

    if not findings:
        add_finding(
            findings,
            case="REMOTE_VIEW_NO_SIGNIFICANT_DIFFERENCE",
            title="Aucune différence remote significative détectée",
            level="OK",
            status=STATUS_ACTIVE,
            confidence=CONFIDENCE_LOW,
            relevance_score=10,
            evidence=[
                f"{working_name} et {failing_name} présentent des observations remote similaires",
            ],
            cause="Les snapshots fournis ne contiennent pas assez d'écarts pour isoler une cause.",
            remediation="Ajouter les erreurs exactes net view/net use ou relancer les diagnostics complets.",
        )

    return add_reasoning_summary(
        sorted_findings(findings),
        working_snapshot,
        failing_snapshot,
        working_shares,
        failing_shares,
        auth_failure,
    )


def add_reasoning_summary(
    findings,
    working_snapshot,
    failing_snapshot,
    working_shares,
    failing_shares,
    auth_failure,
):
    observed = []
    eliminated = []
    suspected = []

    if (
        bool_value(working_snapshot, "remote_tests.tcp_445")
        and bool_value(failing_snapshot, "remote_tests.tcp_445")
    ):
        observed.append("TCP 445 ouvert sur les deux clients")
        eliminated.append("panne serveur SMB")

    if (
        bool_value(working_snapshot, "remote_tests.ping_target")
        and bool_value(failing_snapshot, "remote_tests.ping_target")
    ):
        observed.append("cible joignable")
        eliminated.append("panne réseau")

    if working_shares:
        observed.append("partage visible depuis un client")
        eliminated.append("partage absent")

    if auth_failure or working_shares != failing_shares:
        suspected.extend([
            "authentification SMB",
            "identité Windows",
            "cache d'identifiants",
        ])

    if not observed and not eliminated and not suspected:
        return findings

    summary = {
        "case": "COMPARATIVE_REASONING_SUMMARY",
        "title": "Synthèse du raisonnement comparatif",
        "level": "INFO",
        "status": STATUS_ACTIVE,
        "confidence": CONFIDENCE_PROBABLE,
        "relevance_score": 100,
        "observed": observed,
        "eliminated": list(dict.fromkeys(eliminated)),
        "suspected": list(dict.fromkeys(suspected)),
        "evidence": [
            "Le moteur compare deux points de vue clients vers une même cible.",
        ],
        "cause": (
            "Les observations communes éliminent les causes globales. "
            "Les différences restantes orientent le diagnostic vers le poste client."
        ),
    }

    return [summary] + findings


def build_human_conclusion(findings, working_snapshot, failing_snapshot):
    working_name = machine_name(working_snapshot)
    failing_name = machine_name(failing_snapshot)
    target_name = (
        get_path(working_snapshot, "remote_tests.resolved_name")
        or get_path(failing_snapshot, "remote_tests.resolved_name")
        or get_path(working_snapshot, "remote_agent_snapshot.system.hostname")
        or get_path(failing_snapshot, "remote_agent_snapshot.system.hostname")
        or get_path(working_snapshot, "remote_tests.target")
        or "le serveur cible"
    )
    cases = {finding.get("case") for finding in findings}
    conclusion = []
    proof = []
    likely_causes = []
    actions = []

    if {
        "CAUSE-ELIMINATED-SMB-PORT-BLOCKED",
        "CAUSE-ELIMINATED-TARGET-UNREACHABLE",
    } & cases:
        conclusion.append(f"{with_article(target_name)} fonctionne correctement.")

    if "SMB_ACCESS_DIFFERS_BY_CLIENT" in cases or "SMB_AUTH_DIFFERS_BY_CLIENT" in cases:
        conclusion.append(f"Le problème semble spécifique au poste {failing_name}.")

    if remote_shares(working_snapshot):
        proof.append(f"{working_name} accède au partage ou voit les partages.")

    if bool_value(working_snapshot, "remote_tests.tcp_445") and bool_value(failing_snapshot, "remote_tests.tcp_445"):
        proof.append("Le port SMB (445) répond.")

    if remote_shares(working_snapshot):
        proof.append("Les partages sont visibles depuis au moins un poste.")

    if "SMB_AUTH_DIFFERS_BY_CLIENT" in cases:
        likely_causes.extend([
            "Un identifiant Windows incorrect ou différent.",
            "Un mot de passe mémorisé erroné.",
            f"Une identité Windows différente de celle utilisée sur {working_name}.",
        ])

    elif "SMB_ACCESS_DIFFERS_BY_CLIENT" in cases:
        likely_causes.extend([
            "Une session SMB différente sur le poste en échec.",
            "Des droits ou identifiants différents entre les deux postes.",
            "Un cache d'identifiants Windows à nettoyer.",
        ])

    if likely_causes:
        actions.extend([
            ("Exécuter", "net use * /delete /y"),
            ("Vérifier", "cmdkey /list"),
            ("Réessayer", "avec un compte explicite."),
        ])

    if not conclusion:
        conclusion.append("Le rapport ne contient pas encore assez d'éléments pour isoler une cause simple.")

    return {
        "title": "CONCLUSION",
        "conclusion": conclusion,
        "proof": proof,
        "likely_causes": list(dict.fromkeys(likely_causes)),
        "actions": actions,
    }


def with_article(value):
    text = str(value or "le serveur cible").strip()

    if text.lower().startswith(("le ", "la ", "les ", "l'")):
        return text[:1].upper() + text[1:]

    return f"Le {text}"


def sorted_findings(findings):
    return sorted(
        findings,
        key=lambda item: (
            item.get("status") == STATUS_ELIMINATED,
            -int(item.get("relevance_score") or 0),
            item.get("case") or "",
        ),
    )


def format_findings(findings):
    lines = []

    for finding in findings:
        if finding.get("case") == "COMPARATIVE_REASONING_SUMMARY":
            lines.append("Le moteur a observé :")
            lines.append("")
            for item in finding.get("observed") or []:
                lines.append(f"✓ {item}")

            lines.append("")
            lines.append("Le moteur a donc éliminé :")
            lines.append("")
            for item in finding.get("eliminated") or []:
                lines.append(f"✓ {item}")

            lines.append("")
            lines.append("Le moteur suspecte :")
            lines.append("")
            for item in finding.get("suspected") or []:
                lines.append(f"→ {item}")

            lines.append("")
            continue

        status = finding.get("status") or ""
        confidence = finding.get("confidence") or ""
        if status == STATUS_ELIMINATED:
            tag = "ÉCARTÉ"
        elif finding.get("level") == "WARN":
            tag = "CAUSE PROBABLE"
        else:
            tag = "INFORMATION"

        conf_label = {
            CONFIDENCE_CONFIRMED: "Certitude élevée",
            CONFIDENCE_PROBABLE:  "Confiance élevée",
            CONFIDENCE_LOW:       "Confiance faible",
        }.get(confidence, confidence)

        lines.append(f"[{tag}] {finding.get('title') or ''} ({conf_label})")
        lines.append(f"Explication : {finding.get('cause')}")

        for evidence in finding.get("evidence") or []:
            lines.append(f"  - {evidence}")

        if finding.get("remediation"):
            lines.append(f"Action : {finding.get('remediation')}")

        if finding.get("howto"):
            lines.append("Comment :")
            for label, text in finding.get("howto") or []:
                lines.append(f"  {label}")
                for text_line in str(text).splitlines():
                    lines.append(f"    {text_line}" if text_line else "")

        lines.append("")

    return "\n".join(lines)


def format_human_conclusion(conclusion):
    lines = [conclusion.get("title", "CONCLUSION"), ""]

    for item in conclusion.get("conclusion") or []:
        lines.append(str(item))
        lines.append("")

    proof = conclusion.get("proof") or []
    if proof:
        lines.append("La preuve :")
        for item in proof:
            lines.append(f"- {item}")
        lines.append("")

    causes = conclusion.get("likely_causes") or []
    if causes:
        lines.append("Les causes les plus probables sont :")
        lines.append("")
        for index, item in enumerate(causes, start=1):
            lines.append(f"{index}. {item}")
        lines.append("")

    actions = conclusion.get("actions") or []
    if actions:
        lines.append("Actions recommandées :")
        lines.append("")
        for index, (label, command) in enumerate(actions, start=1):
            lines.append(f"{index}. {label} :")
            lines.append(f"   {command}")
            lines.append("")

    return "\n".join(lines).rstrip()


def snapshot_label(snapshot, fallback):
    name = machine_name(snapshot)
    target = get_path(snapshot, "remote_tests.target")

    if target:
        return f"{name} -> {target}"

    return name or fallback


def target_hostname(working_snapshot, failing_snapshot):
    return (
        get_path(working_snapshot, "remote_tests.resolved_name")
        or get_path(failing_snapshot, "remote_tests.resolved_name")
        or get_path(working_snapshot, "remote_agent_snapshot.system.hostname")
        or get_path(failing_snapshot, "remote_agent_snapshot.system.hostname")
        or get_path(working_snapshot, "remote_tests.target")
        or get_path(failing_snapshot, "remote_tests.target")
        or "inconnu"
    )


def default_output_prefix(working_snapshot, failing_snapshot):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    left = safe_filename(machine_name(working_snapshot))
    right = safe_filename(machine_name(failing_snapshot))
    return f"comparative_analysis_{left}_vs_{right}_{timestamp}"


def safe_filename(value):
    cleaned = "".join(
        char if char.isalnum() or char in ("-", "_") else "_"
        for char in str(value or "unknown")
    ).strip("_")
    return cleaned or "unknown"


def generate_text_report(findings, working_snapshot, failing_snapshot):
    human_conclusion = build_human_conclusion(
        findings,
        working_snapshot,
        failing_snapshot,
    )
    working_machine = machine_name(working_snapshot)
    failing_machine  = machine_name(failing_snapshot)
    target_ip        = (
        get_path(working_snapshot, "remote_tests.target")
        or get_path(failing_snapshot, "remote_tests.target")
        or "?"
    )
    target_host = target_hostname(working_snapshot, failing_snapshot)
    target_label = f"{target_host} ({target_ip})" if target_host != target_ip else target_ip

    lines = [
        "DTLknowsWhy - Rapport de diagnostic",
        "=" * 62,
        f"Connexion testée vers : {target_label}",
        f"Généré le : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
        f"✓ Test depuis {working_machine} : succès",
        f"✗ Test depuis {failing_machine} : échec",
        "",
        format_human_conclusion(human_conclusion),
        "",
        "Synthèse",
        "-" * 62,
        format_findings([
            finding for finding in findings
            if finding.get("case") == "COMPARATIVE_REASONING_SUMMARY"
        ]).strip(),
        "",
        "Différences et explications",
        "-" * 62,
        format_findings([
            finding for finding in findings
            if finding.get("case") != "COMPARATIVE_REASONING_SUMMARY"
        ]).strip(),
        "",
    ]

    return "\n".join(line for line in lines if line is not None)


def score_class(score):
    try:
        score = int(score)
    except (TypeError, ValueError):
        score = 0

    if score >= 90:
        return "score-high"

    if score >= 60:
        return "score-medium"

    return "score-low"


def finding_class(finding):
    if finding.get("status") == STATUS_ELIMINATED:
        return "finding eliminated"

    if finding.get("level") == "WARN":
        return "finding warning"

    if finding.get("level") == "OK":
        return "finding ok"

    return "finding info"


def render_summary_card(title, items, css_class):
    if not items:
        items = ["Aucun élément retenu"]

    rows = "".join(
        f"<li>{escape(str(item))}</li>"
        for item in items
    )
    return f"""
<section class="summary-card {css_class}">
  <h3>{escape(title)}</h3>
  <ul>{rows}</ul>
</section>
"""


def render_human_conclusion_html(conclusion):
    verdict = escape(str((conclusion.get("conclusion") or [""])[0]))
    extra = "".join(
        f"<p>{escape(str(item))}</p>"
        for item in (conclusion.get("conclusion") or [])[1:]
    )
    proof_items = "".join(
        f"<li>{escape(str(item))}</li>"
        for item in conclusion.get("proof") or []
    )
    causes_items = "".join(
        f"<li>{escape(str(item))}</li>"
        for item in conclusion.get("likely_causes") or []
    )

    CMD_NOTES = {
        "net use * /delete /y": "efface les accès réseau enregistrés",
        "cmdkey /list": "liste les mots de passe enregistrés dans Windows",
    }
    actions_items = ""
    for label, command in conclusion.get("actions") or []:
        note = CMD_NOTES.get(command, "")
        note_html = f'<span class="cmd-note">— {escape(note)}</span>' if note else ""
        cmd_html = (
            f'<br><code class="cmd">{escape(command)}</code> {note_html}'
            if not command.startswith("avec")
            else f" {escape(command)}"
        )
        actions_items += f"<li><strong>{escape(label)}</strong>{cmd_html}</li>\n"

    proof_block = (
        f'''<div class="proof"><p>Comment le savons-nous ?</p><ul>{proof_items}</ul></div>'''
        if proof_items else ""
    )
    causes_block = (
        f'''<h3>Causes les plus probables sur ce poste</h3><ol>{causes_items}</ol>'''
        if causes_items else ""
    )
    actions_block = (
        f'''<div class="actions-box"><h3>Ce qu\'il faut faire</h3><ol>{actions_items}</ol></div>'''
        if actions_items else ""
    )

    return f"""
<section class="conclusion">
  <h2>En résumé</h2>
  <p class="verdict">{verdict}</p>
  {extra}
  {proof_block}
  {causes_block}
  {actions_block}
</section>
"""


def render_howto_html(finding):
    rows = []

    for label, text in finding.get("howto") or []:
        body = "<br>".join(escape(str(text)).splitlines())
        rows.append(
            f"<div class=\"howto-step\">"
            f"<h4>{escape(str(label))}</h4>"
            f"<p>{body}</p>"
            f"</div>"
        )

    if not rows:
        return ""

    return f"""
<div class="howto-box">
  <h4>Comment le faire</h4>
  {''.join(rows)}
</div>
"""


def generate_html_report(findings, working_snapshot, failing_snapshot):
    human_conclusion = build_human_conclusion(
        findings,
        working_snapshot,
        failing_snapshot,
    )
    summary = next(
        (
            finding for finding in findings
            if finding.get("case") == "COMPARATIVE_REASONING_SUMMARY"
        ),
        {},
    )
    details = [
        finding for finding in findings
        if finding.get("case") != "COMPARATIVE_REASONING_SUMMARY"
    ]
    detail_html = []

    for finding in details:
        evidence = "".join(
            f"<li>{escape(str(item))}</li>"
            for item in finding.get("evidence") or []
        )
        remediation = (
            f"<p class=\"remediation\"><strong>Action :</strong> {escape(str(finding.get('remediation')))}</p>"
            if finding.get("remediation") else ""
        )
        howto = render_howto_html(finding)
        status = finding.get("status") or ""
        conf   = finding.get("confidence") or ""
        if status == STATUS_ELIMINATED:
            tag_label = "Cause écartée"
            tag_css   = "tag-elim"
        elif finding.get("level") == "WARN":
            tag_label = "Cause probable"
            tag_css   = "tag-warn"
        else:
            tag_label = "Information"
            tag_css   = "tag-info"

        conf_label = {
            CONFIDENCE_CONFIRMED: "Certitude élevée",
            CONFIDENCE_PROBABLE:  "Confiance élevée",
            CONFIDENCE_LOW:       "Confiance faible",
        }.get(conf, escape(conf))

        detail_html.append(f"""
<article class="{finding_class(finding)}">
  <div class="finding-head">
    <h3>{escape(str(finding.get('title') or ''))}</h3>
    <span class="tag {tag_css}">{tag_label}</span>
    <span class="tag tag-conf">{conf_label}</span>
  </div>
  <p>{escape(str(finding.get('cause') or ''))}</p>
  <ul>{evidence}</ul>
  {remediation}
  {howto}
</article>
""")

    t_ip = (
        get_path(working_snapshot, "remote_tests.target")
        or get_path(failing_snapshot, "remote_tests.target")
        or "?"
    )
    t_host = target_hostname(working_snapshot, failing_snapshot)
    target_display = escape(
        f"{t_host} ({t_ip})" if t_host and t_host != t_ip else str(t_ip)
    )

    return f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>DTLknowsWhy &#8211; Rapport de diagnostic comparatif</title>
<style>
:root {{
  --bg: #f3f6fa;
  --panel: #ffffff;
  --line: #c8d4e3;
  --text: #1f2937;
  --muted: #5f6b7a;
  --blue: #0065a8;
  --green: #107c10;
  --orange: #ca5010;
  --red: #d13438;
}}
*, *::before, *::after {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: "Segoe UI", Arial, sans-serif;
  font-size: 15px;
  line-height: 1.6;
  background: var(--bg);
  color: var(--text);
}}
header {{
  background: var(--blue);
  color: white;
  padding: 28px 34px;
}}
header h1 {{
  margin: 0 0 10px;
  font-size: 26px;
  font-weight: 600;
}}
.header-meta {{
  margin: 0 0 10px;
  opacity: 0.88;
  font-size: 14px;
}}
.header-result {{
  margin: 4px 0 0;
  font-size: 15px;
  font-weight: 600;
}}
.ok-result   {{ color: #a8e6a8; }}
.fail-result {{ color: #ffb3b3; }}
main {{
  padding: 28px 34px 48px;
  max-width: 1100px;
}}
.conclusion {{
  background: #fff;
  border: 1px solid var(--line);
  border-left: 6px solid var(--green);
  padding: 22px 24px 18px;
  margin-bottom: 28px;
}}
.conclusion h2 {{
  margin: 0 0 6px;
  color: var(--green);
  font-size: 20px;
}}
.conclusion .verdict {{
  font-size: 17px;
  font-weight: 600;
  margin: 0 0 16px;
  color: var(--text);
}}
.conclusion .proof {{
  background: #f3f9f3;
  border: 1px solid #c3dfc3;
  padding: 12px 16px;
  margin-bottom: 16px;
}}
.conclusion .proof p {{
  margin: 0 0 6px;
  font-weight: 600;
  color: var(--green);
}}
.conclusion .proof ul {{
  margin: 0;
  padding-left: 20px;
}}
.conclusion ol {{
  margin: 0;
  padding-left: 22px;
}}
.conclusion ol li {{
  margin-bottom: 6px;
}}
.conclusion h3 {{
  margin: 16px 0 8px;
  font-size: 15px;
  color: var(--text);
}}
.actions-box {{
  margin-top: 18px;
  background: #f8fbff;
  border: 1px solid #dbe7f5;
  padding: 16px 18px;
}}
.actions-box h3 {{
  margin: 0 0 10px;
  font-size: 15px;
  color: var(--blue);
}}
.actions-box ol {{
  margin: 0;
  padding-left: 22px;
}}
.actions-box li {{
  margin-bottom: 10px;
}}
.actions-box .cmd {{
  display: inline-block;
  margin-top: 4px;
  padding: 5px 10px;
  background: #101820;
  color: #e7f0fa;
  font-family: "Cascadia Mono", "Consolas", monospace;
  font-size: 13px;
  border-radius: 3px;
}}
.actions-box .cmd-note {{
  font-size: 13px;
  color: var(--muted);
  margin-left: 6px;
}}
.summary-grid {{
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px;
  margin-bottom: 28px;
}}
.summary-card {{
  background: var(--panel);
  border: 1px solid var(--line);
  border-top: 4px solid var(--blue);
  padding: 16px 18px;
}}
.summary-card.observed  {{ border-top-color: var(--green); }}
.summary-card.suspected {{ border-top-color: var(--orange); }}
.summary-card.eliminated-card {{ border-top-color: var(--blue); }}
.summary-card h3 {{
  margin: 0 0 10px;
  font-size: 14px;
  text-transform: uppercase;
  letter-spacing: .04em;
  color: var(--muted);
}}
.summary-card ul {{
  margin: 0;
  padding-left: 18px;
}}
.summary-card li {{
  margin-bottom: 4px;
}}
h2.section-title {{
  margin: 0 0 16px;
  font-size: 18px;
  color: var(--text);
  border-bottom: 2px solid var(--line);
  padding-bottom: 8px;
}}
.finding {{
  background: var(--panel);
  border: 1px solid var(--line);
  border-left: 5px solid var(--blue);
  padding: 18px 20px;
  margin-bottom: 14px;
}}
.finding.warning  {{ border-left-color: var(--orange); }}
.finding.eliminated {{ border-left-color: var(--green); }}
.finding.info     {{ border-left-color: var(--blue); }}
.finding-head {{
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 10px;
  margin-bottom: 10px;
}}
.finding-head h3 {{
  margin: 0;
  font-size: 16px;
  flex: 1 1 auto;
}}
.tag {{
  font-size: 12px;
  font-weight: 700;
  padding: 2px 9px;
  border-radius: 2px;
  white-space: nowrap;
}}
.tag-warn {{ background: #fff3e0; color: var(--orange); border: 1px solid #f5c98a; }}
.tag-elim {{ background: #e8f5e9; color: var(--green);  border: 1px solid #a5d6a7; }}
.tag-info {{ background: #e3f0fb; color: var(--blue);   border: 1px solid #90c4f0; }}
.tag-conf {{ background: #fafafa; color: var(--muted);  border: 1px solid var(--line); }}
.finding p {{ margin: 0 0 10px; }}
.finding ul {{ margin: 0 0 10px; padding-left: 20px; }}
.finding li {{ margin-bottom: 4px; }}
.remediation {{
  background: #f8fbff;
  border: 1px solid #dbe7f5;
  padding: 10px 14px;
  font-size: 14px;
  margin-top: 10px;
}}
.remediation strong {{ color: var(--blue); }}
.howto-box {{
  background: #fffdf7;
  border: 1px solid #ead7a4;
  padding: 12px 14px;
  margin-top: 12px;
}}
.howto-box > h4 {{
  margin: 0 0 10px;
  color: var(--orange);
  font-size: 14px;
  text-transform: uppercase;
  letter-spacing: .04em;
}}
.howto-step {{
  border-top: 1px solid #f0e2bd;
  padding-top: 9px;
  margin-top: 9px;
}}
.howto-step:first-of-type {{
  border-top: 0;
  padding-top: 0;
  margin-top: 0;
}}
.howto-step h4 {{
  margin: 0 0 4px;
  font-size: 13px;
  color: var(--text);
}}
.howto-step p {{
  margin: 0;
  font-family: "Cascadia Mono", "Consolas", monospace;
  font-size: 13px;
  white-space: normal;
}}
@media (max-width: 780px) {{
  .summary-grid {{ grid-template-columns: 1fr; }}
  main {{ padding: 18px 16px 36px; }}
}}
</style>
</head>
<body>
<header>
  <h1>Rapport de diagnostic &#8211; Connexion vers {target_display}</h1>
  <p class="header-meta">Généré le : <strong>{escape(datetime.now().strftime('%d/%m/%Y %H:%M:%S'))}</strong></p>
  <p class="header-result ok-result">&#10003; Test depuis <strong>{escape(machine_name(working_snapshot))}</strong> : succès</p>
  <p class="header-result fail-result">&#10007; Test depuis <strong>{escape(machine_name(failing_snapshot))}</strong> : échec</p>
</header>
<main>
  {render_human_conclusion_html(human_conclusion)}
  <section class="summary-grid">
    {render_summary_card("Le moteur a observé", summary.get("observed"), "observed")}
    {render_summary_card("Le moteur a donc éliminé", summary.get("eliminated"), "eliminated-card")}
    {render_summary_card("Le moteur suspecte", summary.get("suspected"), "suspected")}
  </section>
  <section>
    <h2 class="section-title">Analyses détaillées</h2>
    {''.join(detail_html)}
  </section>
</main>
</body>
</html>
"""


def write_reports(findings, working_snapshot, failing_snapshot, output_prefix=None):
    prefix = output_prefix or default_output_prefix(working_snapshot, failing_snapshot)
    json_path = Path(f"{prefix}.json")
    text_path = Path(f"{prefix}.txt")
    html_path = Path(f"{prefix}.html")

    json_path.write_text(
        json.dumps(findings, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    text_path.write_text(
        generate_text_report(findings, working_snapshot, failing_snapshot),
        encoding="utf-8",
    )
    html_path.write_text(
        generate_html_report(findings, working_snapshot, failing_snapshot),
        encoding="utf-8",
    )

    return json_path, text_path, html_path


def main():
    parser = argparse.ArgumentParser(
        description="Compare two DTLknowsWhy remote diagnostics."
    )
    parser.add_argument("working_snapshot", help="Snapshot where access works")
    parser.add_argument("failing_snapshot", help="Snapshot where access fails")
    parser.add_argument("--lang", default="fr", choices=("fr", "en"))
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument(
        "--output-prefix",
        help="Output path prefix for TXT and HTML reports",
    )
    parser.add_argument(
        "--no-files",
        action="store_true",
        help="Do not write TXT/HTML report files",
    )
    args = parser.parse_args()
    working_snapshot = load_snapshot(args.working_snapshot)
    failing_snapshot = load_snapshot(args.failing_snapshot)

    findings = compare_remote_diagnostics(
        working_snapshot,
        failing_snapshot,
        args.lang,
    )

    if not args.no_files:
        json_path, text_path, html_path = write_reports(
            findings,
            working_snapshot,
            failing_snapshot,
            args.output_prefix,
        )
        print(f"Rapport JSON  : {json_path}")
        print(f"Rapport texte : {text_path}")
        print(f"Rapport HTML  : {html_path}")

    if args.json:
        print(json.dumps(findings, ensure_ascii=False, indent=2))
    else:
        print(format_findings(findings))


if __name__ == "__main__":
    main()
