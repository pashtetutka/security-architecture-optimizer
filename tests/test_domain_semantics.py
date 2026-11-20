from decimal import Decimal
import unittest

from siem.domain import (compare_quantity, compare_versions, convert_quantity,
                         evaluate_conditions)
from siem.domain.contracts import TruthValue


def version(value, scheme='dotted_numeric'):
    return {'raw':value,'kind':'exact','scheme':scheme,'values':[value],
            'lower':None,'upper':None,'bounds':None,'status':'known'}


def quantity(value, unit, basis='total'):
    return {'value':value,'unit':unit,'basis':basis,'raw':str(value)}


class VersionTests(unittest.TestCase):
    def test_exact_does_not_promote_major(self):
        self.assertEqual('mismatch',compare_versions(version('4'),version('4.5')).status)
        self.assertEqual('mismatch',compare_versions(version('6.5'),version('6.5.7')).status)
        self.assertEqual('mismatch',compare_versions(version('2008','windows_release'),version('2008 R2','windows_release')).status)

    def test_range_inclusivity_and_opaque(self):
        published={'kind':'range','scheme':'dotted_numeric','values':[],'lower':'4','upper':'5',
                   'bounds':{'lower_inclusive':False,'upper_inclusive':True},'status':'known','raw':'(4,5]'}
        self.assertEqual('mismatch',compare_versions(version('4'),published).status)
        self.assertEqual('match',compare_versions(version('5'),published).status)
        self.assertEqual('unknown',compare_versions(version('x','opaque'),version('x','opaque')).status)

    def test_missing_boundary_inclusion_is_indeterminate_only_at_boundary(self):
        published = {'kind': 'range', 'scheme': 'dotted_numeric', 'lower': '4', 'upper': '5',
                     'bounds': {'lower_inclusive': None, 'upper_inclusive': None},
                     'status': 'parsed'}
        for value, expected in [('3', 'mismatch'), ('4', 'unknown'), ('4.5', 'match'),
                                ('5', 'unknown'), ('6', 'mismatch')]:
            with self.subTest(value=value):
                self.assertEqual(expected, compare_versions(version(value), published).status)

class QuantityTests(unittest.TestCase):
    def test_conversion_is_reversible(self):
        original=quantity(16,'GiB')
        restored=convert_quantity(convert_quantity(original,'B'),'GiB')
        self.assertEqual(Decimal(16),restored['value'])

    def test_unknown_basis_and_cpu_units_are_not_guessed(self):
        self.assertEqual('unknown',compare_quantity(quantity(4,'physical_cores'),quantity(8,'vCPU')).status)
        self.assertEqual('unknown',compare_quantity(quantity(4,'GB','per_node'),quantity(8,'GB','total')).status)
        self.assertEqual('unknown',compare_quantity(quantity(None,'GB'),quantity(8,'GB')).status)

class ConditionTests(unittest.TestCase):
    def test_unknown_required_atom_propagates(self):
        atom={'operator':'gte','operands':{'metric':'ram','subject_ref':'node:a','value':quantity(16,'GB')}}
        self.assertEqual(TruthValue.UNKNOWN,evaluate_conditions(atom,{}))
        group={'operator':'all_of','operands':[atom,{'operator':'eq','operands':{'metric':'os','subject_ref':'node:a','value':{'type':'string','value':'linux'}}}]}
        self.assertEqual(TruthValue.UNKNOWN,evaluate_conditions(group,{'node:a':{'os':{'value':'linux'}}}))

    def test_any_of_and_mandatory_all_of(self):
        linux={'operator':'eq','operands':{'metric':'os','subject_ref':'node:a','value':{'type':'string','value':'linux'}}}
        windows={'operator':'eq','operands':{'metric':'os','subject_ref':'node:a','value':{'type':'string','value':'windows'}}}
        alternatives={'operator':'any_of','operands':[linux,windows]}
        self.assertEqual(TruthValue.TRUE,evaluate_conditions(alternatives,{'node:a':{'os':{'value':'windows'}}}))

if __name__ == '__main__': unittest.main()
