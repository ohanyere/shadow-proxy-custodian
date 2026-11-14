"""Strict recovery evidence: successful repair never implies clean execution."""
import re


def inventory(value):
    if not isinstance(value, dict) or set(value) != {'containers', 'networks'}:
        raise ValueError('Invalid inventory fields')
    for ids in value.values():
        if not isinstance(ids, list) or any(not isinstance(i, str) or not re.fullmatch('[0-9a-f]{64}', i) for i in ids):
            raise ValueError('Invalid immutable Docker IDs')
        if len(ids) != len(set(ids)): raise ValueError('Duplicate resource identity')
    return {key: sorted(ids) for key, ids in value.items()}


def assess(before, initial, final, recovery):
    before, initial, final = map(inventory, (before, initial, final))
    required = {'clean', 'initial', 'final', 'orphans_detected', 'deleted_owned', 'errors'}
    if not isinstance(recovery, dict) or set(recovery) != required:
        raise ValueError('Incomplete recovery evidence')
    if type(recovery['clean']) is not bool or not isinstance(recovery['errors'], list):
        raise ValueError('Malformed recovery outcome')
    if inventory(recovery['initial']) != initial or inventory(recovery['final']) != final:
        raise ValueError('Recovery inventories contradict independent snapshots')
    orphan = sorted(set(initial['containers']+initial['networks']) - set(before['containers']+before['networks']))
    reported = recovery['orphans_detected']; deleted = recovery['deleted_owned']
    for values in (reported, deleted):
        if not isinstance(values, list) or any(not isinstance(i, str) for i in values) or len(set(values)) != len(values):
            raise ValueError('Invalid recovery identities')
    if sorted(reported) != orphan or not set(deleted) <= set(orphan):
        raise ValueError('Recovery ownership/evidence contradiction')
    removed = set(initial['containers']+initial['networks']) - set(final['containers']+final['networks'])
    if removed != set(deleted): raise ValueError('Unexplained resource removal')
    restored = final == before and not recovery['errors']
    if recovery['clean'] != restored: raise ValueError('Contradictory clean claim')
    necessary = initial != before or bool(deleted)
    return {'recovery_required': necessary, 'recovery_succeeded': restored,
            'cleanup_verified': restored and not necessary, 'orphans_detected': orphan,
            'initial_inventory': initial, 'final_inventory': final}
