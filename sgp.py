#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import logging
import os
import proxmoxer
import sys
import time

from proxmoxer.core import ResourceException
from typing import Dict, Optional

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('sgp')


def load_config(config_file: str) -> Dict:
    """
    Load configuration from a JSON file and validate rules.

    Args:
        config_file: Path to the JSON configuration file.

    Returns:
        Dictionary containing the validated configuration.
    """
    try:
        if not os.path.exists(config_file):
            raise Exception(f"'{config_file}' not found.")

        with open(config_file, 'r') as f:
            config = json.load(f)

        logger.info(f"Configuration: '{config_file}' loaded successfully.")

        # Validate the configuration structure
        # mandatory configuration sections are 'proxmox' and 'rules'
        mandatory_sections = ['proxmox', 'rules']
        for section in mandatory_sections:
            if section not in config:
                raise Exception(f"missing '{section}' section.")

        # In 'proxmox' section
        # 'host', 'user', 'token_name', 'token_value'
        #  are mandatory fields
        mandatory_fields = ['host', 'user', 'token_name', 'token_value']
        for field in mandatory_fields:
            if field not in config['proxmox']:
                raise Exception(f"'{field}' in 'proxmox' section missing.")

        # Validate and filter rules
        valid_rules = []
        for i, rule in enumerate(config['rules']):
            # we use the validate_rule function to check
            # if the rule is valid
            if validate_rule(i, rule):
                valid_rules.append(rule)
            else:
                # if the rule has no name we default to its index
                name = rule.get('name', f"#{i}")
                # if the rule is invalid we log a warning
                logger.warning(f"Configuration: rule '{name}' is invalid.")

        # Replace rules with validated rules
        config['rules'] = valid_rules

        # Check if there are any valid rules
        if not valid_rules:
            raise Exception("no valid rules found.")

        logger.info(f"Configuration: loaded {len(valid_rules)} valid rules.")

        # Set default values for retry mechanism
        if 'retry' not in config:
            config['retry'] = {
                'max_attempts': 3,  # the number of attempts to retry
                'delay_seconds': 1  # the delay between attempts in seconds
            }
        elif 'max_attempts' not in config['retry'] or config['retry']['max_attempts'] < 1:
            config['retry']['max_attempts'] = 3
        elif 'delay_seconds' not in config['retry'] or config['retry']['delay_seconds'] < 1:
            config['retry']['delay_seconds'] = 1

        return config

    except json.JSONDecodeError as e:
        logger.error(f"Configuration: error parsing configuration file: {e}")
    except Exception as e:
        logger.error(f"Configuration: error loading configuration: {e}")

    sys.exit(1)


def validate_rule(i: int, rule: Dict) -> bool:
    """
    Validate a rule configuration.

    Args:
        i: The index of the rule.
        rule: The rule to validate.

    Returns:
        True if the rule is valid, False otherwise.
    """
    # if the rule has no name we default to its index
    if 'name' not in rule:
        rule['name'] = f'#{i}'
        logger.warning(f"Rule '{rule['name']}': missing 'name' field, setting to '{rule['name']}'.")

    # Check mandatory fields
    # 'tags' and 'security_groups' are mandatory fields
    # for a rule to be valid
    mandatory_fields = ['tags', 'security_groups']
    for field in mandatory_fields:
        if field not in rule:
            logger.error(f"Rule '{rule['name']}': mandatory field '{field}' missing.")
            return False

    # Check tags structure
    # tags section needs to have a 'taglist'
    if 'taglist' not in rule['tags']:
        logger.error(f"Rule '{rule['name']}': 'taglist' field in 'tags' section missing.")
        return False

    # Set default matching if not present
    # the 'matching' field in 'tags' section is defaulted to 'any'
    # if it is not present or invalid
    if 'matching' not in rule['tags'] or rule['tags']['matching'] not in ['any', 'all']:
        logger.warning(f"Rule '{rule['name']}': 'matching' field in 'tags' section missing, setting to default value 'any'")
        rule['tags']['matching'] = 'any'

    # Set default values for optional fields
    optional_fields = {
        'desired_status': ['running'],
        'force_top': True,
        'input_policy': 'DROP',
        'output_policy': 'ACCEPT',
    }

    for field, default_value in optional_fields.items():
        if field not in rule or (
            (field == 'input_policy' or field == 'output_policy') and rule[field] not in ['ACCEPT', 'DROP']
        ):
            logger.debug(f"Rule '{rule['name']}': 'optional field '{field}' missing, setting to default value '{default_value}'")
            rule[field] = default_value

    return True


class Proxmox:
    """Singleton class for Proxmox API connection."""
    _instance = None
    _proxmox = None
    _config = None

    # Singleton pattern to ensure only one instance of Proxmox API connection
    def __new__(cls, config: Optional[Dict] = None):
        if cls._instance is None:
            cls._instance = super(Proxmox, cls).__new__(cls)
            if config:
                cls._config = config

        return cls._instance

    @classmethod
    def connect(cls) -> None:
        """Establish connection to Proxmox API using API token."""
        try:

            proxmox_config = cls._config.get('proxmox')

            # Connect using API token
            cls._proxmox = proxmoxer.ProxmoxAPI(
                proxmox_config['host'],
                port=proxmox_config.get('port', 8006),
                user=proxmox_config['user'],
                token_name=proxmox_config['token_name'],
                token_value=proxmox_config['token_value'],
                verify_ssl=proxmox_config.get('verify_ssl', False)
            )
            logger.info(f"PVE API: connected to {proxmox_config['host']}.")
        except Exception as e:
            logger.error(f"PVE API: error => {e}")
            sys.exit(1)

    @classmethod
    @property
    def pve(cls):
        """Get the Proxmox API connection."""
        if cls._proxmox is None:
            cls.connect()
        return cls._proxmox

    @classmethod
    def _retry_operation(cls, operation_name, endpoint, operation_func):
        """
        Retry an operation with a basic retry mechanism.
        Args:
            operation_name: The name of the operation.
            endpoint: The endpoint for the operation.
            operation_func: The function to execute.
        Returns:
            the result of operation_func or False.
        """

        max_attempts = cls._config['retry']['max_attempts']
        delay_seconds = cls._config['retry']['delay_seconds']

        for current_attempt in range(max_attempts):
            try:
                return operation_func(endpoint)
            except ResourceException as e:
                if current_attempt < max_attempts - 1:
                    logger.warning(
                        f"Attempt no. {current_attempt + 1} for {operation_name} failed ({e}). "
                        f"Retrying in {delay_seconds} seconds..."
                    )
                    time.sleep(delay_seconds)
                else:
                    logger.error(f"All attempts for {operation_name} failed ({e}).")

        return False

    @classmethod
    def add_new_group(cls, group_endpoint, group_name) -> bool:
        """
        Add a new security group to the top of the rules list.

        Args:
            group_endpoint: The endpoint for the group.
            group_name: The name of the new group.

        Returns:
            True if the group was added, False otherwise.
        """
        def add_operation(endpoint):
            endpoint.post(action=group_name, enable=1, type='group')
            return True

        def operation(endpoint):
            try:
                group_name = endpoint.get()['action']
            except Exception:
                group_name = "unknown"

            return f"adding group {group_name}"

        operation_name = operation(group_endpoint)
        return cls._retry_operation(operation_name, group_endpoint, add_operation)

    @classmethod
    def move_group(cls, group_endpoint, position) -> bool:
        """
        Move a group to a new position.

        Args:
            group_endpoint: The endpoint for the group.
            position: The new position for the group.

        Returns:
            True if the group was moved, False otherwise.
        """
        def move_operation(endpoint):
            group = endpoint.get()
            if group:
                endpoint.put(moveto=position, digest=group['digest'])
                return True

            return False

        def operation(endpoint):
            try:
                group_name = endpoint.get()['action']
            except Exception:
                group_name = "unknown"

            return f"moving group {group_name}"

        operation_name = operation(group_endpoint)
        return cls._retry_operation(operation_name, group_endpoint, move_operation)

    @classmethod
    def enable_group_if_needed(cls, group_endpoint) -> bool:
        """
        Enable a group if it is not already enabled.

        Args:
            group_endpoint: The endpoint for the group.

        Returns:
            True if the group was enabled, False otherwise.
        """
        def enable_operation(endpoint):
            group = endpoint.get()
            if group['enable'] == 1:
                return False
            endpoint.put(enable=1, digest=group['digest'])
            return True

        def operation(endpoint):
            try:
                group_name = endpoint.get()['action']
            except Exception:
                group_name = "unknown"

            return f"enabling group {group_name}"

        operation_name = operation(group_endpoint)
        return cls._retry_operation(operation_name, group_endpoint, enable_operation)

    @classmethod
    def rule_selector(cls, va) -> Optional[Dict]:
        # available security groups (at cluster level)
        security_groups = [sg['group'].strip() for sg in cls.pve.cluster.firewall.groups.get()]

        # enumerate tags for the VM/CT
        va['tags'] = va['tags'].strip().split(';') if 'tags' in va and va['tags'].strip() else []

        for rule in cls._config['rules']:
            # looping through rules
            logger.info(f"VM/CT '{va['name']}': checking rule => {rule['name']}")

            # First of all we check if the security groups specified within the rule
            # can be actually found among the security groups defined at cluster level
            if 'security_groups' in rule:
                if not all(sg in security_groups for sg in rule['security_groups']):
                    groups = "', '".join(rule['security_groups'])
                    logger.warning(f"Rule '{rule['name']}': security groups '{groups}' are not valid or not defined")
                    continue

            # Check if the VM/CT status matches the desired status
            # eventually we propagate security groups to the VM/CT
            # if it is in the desired status as specified within the rule
            if va['status'] not in rule['desired_status']:
                logger.info(f"VM/CT '{va['name']}': status '{va['status']}' not matching desired status '{rule['desired_status']}'.")
                continue

            # Check if the VM/CT tags match the rule's tags
            # security groups are propagated to the VM/CT
            # if the tags specified in the rule are applied to the VM/CT
            # according to the matching criterion (any/all)
            if 'tags' not in rule:
                logger.warning(f"Rule '{rule['name']}' does not specify tags")
                continue

            f = any if rule['tags']['matching'] == 'any' else all
            if not f(tag in va['tags'] for tag in rule['tags']['taglist']):
                logger.info(
                    f"VM/CT {va['name']}, tags '{va['tags']}' do not match rule tags '{rule['tags']['taglist']}' "
                    f"with matching criterion '{rule['tags']['matching']}'"
                )
                continue

            return rule

        logger.debug(f"No matching rule found for the VM/CT {va['name']}")
        return None

    @classmethod
    def rule_propagator(cls, node, va, propagation_rule) -> bool:
        """
        Apply the selected rule to the VM/CT.

        Args:
            va: The VM/CT object.
            rule: The rule to apply.
        """
        logger.info(f"Rule '{propagation_rule['name']}': propagating to VM/CT {va['name']}")

        # takes into account the number of actions performed
        # on the configuration to propagate the rule
        propagation_action_count = 0

        # pos_to_force is the position of the securty group contained in the rule to be propagated
        # whereas group_to_propagate is the security group to be propagated itself
        for pos_to_force, group_to_propagate in enumerate(propagation_rule['security_groups']):

            # (re)load rules and groups
            va_endpoint = getattr(node, 'lxc' if 'type' in va and va['type'] == 'lxc' else 'qemu')(va['vmid'])
            enforced_rules = va_endpoint.firewall.rules

            found = False

            # iterate through the enforced secuirity groups
            for enforced_group in enforced_rules.get():
                if enforced_group.get('type') != 'group':
                    continue

                enforced_pos = enforced_group['pos']
                enforced_name = enforced_group['action']

                # check if the group we are trying to propagate is already enforced on the VM/CT
                if group_to_propagate == enforced_name:

                    # the group is already enforced and we ensure it is enabled
                    if cls.enable_group_if_needed(enforced_rules(enforced_pos)):
                        propagation_action_count += 1
                        break

                    # also, according to the configuration, we ensure the group is at the top of the list
                    if propagation_rule['force_top'] and enforced_pos != pos_to_force:
                        if cls.move_group(enforced_rules(enforced_pos), pos_to_force):
                            propagation_action_count += 1

                    found = True
                    break

            if not found:
                logger.info(f"Rule '{propagation_rule['name']}': group '{group_to_propagate}' not found in VM/CT {va['name']}")

                # add group to the top of the list
                if cls.add_new_group(enforced_rules, group_to_propagate):
                    logger.info(f"Rule '{propagation_rule['name']}': group '{group_to_propagate}' added to VM/CT {va['name']}")
                    propagation_action_count += 1

                if not propagation_rule['force_top']:
                    # we have to move to the bottom of the list
                    pos = len(enforced_rules.get())

                    # propagate the rule (enable and enforce top position)
                    if cls.move_group(enforced_rules(0), pos):
                        propagation_action_count += 1

            if propagation_action_count > 0:
                # ensure input and output policies are applied
                va_endpoint.firewall.options.put(enable=1,
                                                 policy_in=propagation_rule['input_policy'],
                                                 policy_out=propagation_rule['output_policy'])

            return propagation_action_count > 0

    @classmethod
    def rule_enforcer(cls) -> int:
        """
        Get a list of all VMs and containers.

        Returns:
            List of dictionaries containing VM and container information.
        """

        enforced_rules_count = 0
        # try:

        for node in cls.pve.nodes.get():
            node_name = node["node"]

            if 'exclude' in cls._config and 'node_names' in cls._config['exclude']:
                if node_name in cls._config['exclude']['node_names']:
                    logger.info(f"Node {node_name}: excluding")
                    continue

            pve = cls.pve.nodes(node_name)

            # VMs and CTs are virtual appliances.
            # using VAs to refer to them
            all_vas = pve.qemu.get()
            all_vas.extend(pve.lxc.get())
            logger.info(f"Node {node_name}: found {len(all_vas)} VMs/CTs")

            for va in all_vas:
                if 'exclude' in cls._config and 'va_ids' in cls._config['exclude']:
                    if node_name in cls._config['exclude']['va_ids']:
                        logger.info(f"VM/CT {va['name']}: excluding")
                        continue

                # select a suitable rule for this VM/CT
                rule = cls.rule_selector(va)
                if rule is None:
                    logger.debug(f"VM/CT {va['name']}: no rule selected")
                    continue

                logger.info(f"VM/CT {va['name']}: selected rule => {rule['name']}")

                propagated = cls.rule_propagator(pve, va, rule)
                if propagated:
                    enforced_rules_count += 1

        # except Exception as e:
        #     logger.error(f"Error retrieving VMs and containers: {e}")

        return enforced_rules_count


def parse_arguments():
    """
    Parse command line arguments.

    Returns:
        Namespace object containing the parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description='Security Group Propagator for Proxmox VE',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        '-c', '--config',
        default='config.json',
        help='Path to the configuration file'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Increase output verbosity'
    )

    return parser.parse_args()


def main():
    # Parse command line arguments
    args = parse_arguments()

    # Adjust logging level based on verbosity
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger.setLevel(log_level)

    # Load configuration from file
    config = load_config(args.config)

    proxmox = Proxmox(config)
    proxmox.connect()

    enforced_count = proxmox.rule_enforcer()
    logger.info(f"Enforced {enforced_count} rules")

    return 0


if __name__ == "__main__":
    main()
