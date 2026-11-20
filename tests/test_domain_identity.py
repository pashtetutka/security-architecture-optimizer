import json
from pathlib import Path
import unittest

from siem.domain.identity import (IdentityDictionary, ResolutionContext,
                                  load_default_dictionary, normalize_identity, resolve_name, unresolved_queue)
from siem.domain.contracts import ResolutionStatus


ROOT = Path(__file__).resolve().parents[1]


class IdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dictionary = IdentityDictionary.load(ROOT / 'tests/fixtures/identity_dictionary.v2.json')

    def test_normalization_is_idempotent_and_unicode_aware(self):
        samples = ['  1C:Предприятие  ', 'КИБЕР‑БЭКАП', 'Ежик и Ёлка', 'C', 'C++', 'C#']
        for sample in samples:
            once = normalize_identity(sample)
            self.assertEqual(once, normalize_identity(once))
        self.assertNotEqual(normalize_identity('C'), normalize_identity('C++'))
        self.assertNotEqual(normalize_identity('C++'), normalize_identity('C#'))

    def test_explicit_equivalences_share_stable_entity(self):
        names = ['Кибербэкап', 'Кибер Бэкап', 'Cyber Backup']
        refs = {resolve_name(name, None, self.dictionary).entity_ref for name in names}
        self.assertEqual({'product:cyberprotect-cyber-backup'}, refs)
        self.assertNotEqual(resolve_name('Cyberprotect', None, self.dictionary).entity_ref,
                            next(iter(refs)))
        self.assertEqual(resolve_name('1C:Предприятие', None, self.dictionary).entity_ref,
                         resolve_name('1С:Предприятие', None, self.dictionary).entity_ref)

    def test_context_resolves_collision_without_siem_specific_rule(self):
        bare = resolve_name('Gateway', None, self.dictionary)
        self.assertEqual(ResolutionStatus.UNRESOLVED, bare.status)
        network = resolve_name('Gateway', ResolutionContext(vendor_ref='vendor:microsoft'), self.dictionary)
        mail = resolve_name('Gateway', {'vendor_ref': 'vendor:cyberprotect'}, self.dictionary)
        self.assertEqual('product:gateway-network', network.entity_ref)
        self.assertEqual('product:gateway-mail', mail.entity_ref)

    def test_unknown_and_ambiguous_are_diagnostic(self):
        unknown = resolve_name('Новый неизвестный продукт', None, self.dictionary)
        self.assertEqual(ResolutionStatus.UNRESOLVED, unknown.status)
        self.assertEqual(1, len(unresolved_queue([unknown])))

    def test_dictionary_validation_rejects_cycles_by_reference_or_bad_key(self):
        raw = json.loads((ROOT / 'tests/fixtures/identity_dictionary.v2.json').read_text('utf-8'))
        raw['aliases'][0]['normalized_key'] = 'wrong'
        with self.assertRaisesRegex(ValueError, 'normalized_key mismatch'):
            IdentityDictionary.from_dict(raw)

    def test_display_name_update_does_not_change_explicit_id(self):
        raw = json.loads((ROOT / 'tests/fixtures/identity_dictionary.v2.json').read_text('utf-8'))
        raw['entities'][1]['display_name'] = 'Cyber Backup (renamed display)'
        changed = IdentityDictionary.from_dict(raw)
        self.assertEqual('product:cyberprotect-cyber-backup',
                         resolve_name('Кибербэкап', None, changed).entity_ref)

    def test_every_legacy_alias_has_an_explicit_migration_decision(self):
        from siem.etl.coverage import ALIAS
        raw = json.loads((ROOT / 'tests/fixtures/identity_dictionary.v2.json').read_text('utf-8'))
        decisions = {row['legacy_surface']: row for row in raw['legacy_migration']['decisions']}
        self.assertEqual(set(ALIAS), set(decisions))
        for surface in ALIAS:
            decision = decisions[surface]
            if decision['decision'] == 'equivalence':
                self.assertEqual(ResolutionStatus.RESOLVED,
                                 resolve_name(surface, None, self.dictionary).status)
            else:
                self.assertEqual('eltex switch', surface)

    def test_packaged_dictionary_default(self):
        latest=IdentityDictionary.load(ROOT/'src/siem/domain/ontology/identity_dictionary.v6.json')
        self.assertEqual(latest.version,load_default_dictionary().version)
        self.assertEqual('product:microsoft-windows-server',
                         resolve_name('Microsoft Windows Server', None, latest).entity_ref)


if __name__ == '__main__':
    unittest.main()
