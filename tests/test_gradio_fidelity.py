"""Gradio/Space parameter & control fidelity (LSCAN-011): the attack lands in the intended named parameter, and a Space
with fixed instructions is not assessed as if the scanner controlled them."""
from hfsentinel.targets.gradio_fidelity import analyze_endpoint, system_prompt_technique_applicable


def test_attack_lands_in_the_user_message_parameter():
    f = analyze_endpoint("/chat", [{"name": "system_prompt", "type": "str"},
                                   {"name": "message", "type": "str"},
                                   {"name": "temperature", "type": "float"}])
    assert f.attack_param == "message"          # not system_prompt, not temperature
    assert f.system_param == "system_prompt" and f.scanner_controls_system
    assert system_prompt_technique_applicable(f)


def test_fixed_instruction_space_is_not_scanner_controlled():
    # a Space that only takes the user's text — its instructions are fixed server-side
    f = analyze_endpoint("/predict", [{"name": "user_input", "type": "str"}])
    assert f.attack_param == "user_input" and f.system_param is None
    assert not f.scanner_controls_system
    assert not system_prompt_technique_applicable(f)  # system-prompt techniques are N/A, not scanner-controlled


def test_text_only_function_without_hinted_name_uses_first_string_param():
    f = analyze_endpoint("/run", [{"name": "arg0", "type": "str"}, {"name": "max_tokens", "type": "int"}])
    assert f.attack_param == "arg0"


def test_no_string_parameter_means_no_attack_slot():
    f = analyze_endpoint("/img", [{"name": "seed", "type": "int"}])
    assert f.attack_param is None
