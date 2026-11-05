"""Gradient, assumption-led SIEM fit assessment. Not procurement recommendation.
No-support != unsupported. All costs are customer-supplied estimates, NEVER vendor quotes.
"""
from __future__ import annotations
import re
from collections import Counter
from .coverage import canonical as domain_canonical

def canonical(x):
 return domain_canonical(x)

def _version_matches(requested, published):
 """Match only explicit list items and numeric published ranges."""
 requested=str(requested or '').strip().casefold()
 published=str(published or '').strip().casefold()
 if not requested or not published:
  return False
 values=[part.strip() for part in re.split(r'[,;]|\s+и\s+',published) if part.strip()]
 if requested in values:
  return True
 numeric=lambda value: tuple(int(part) for part in value.split('.'))
 number=r'(\d+(?:\.\d+)*)'
 try:
  asked=numeric(requested)
 except ValueError:
  return False
 for value in values:
  match=re.fullmatch(number+r'\s*[-–—]\s*'+number,value)
  if match:
   try:
    if numeric(match.group(1)) <= asked <= numeric(match.group(2)):
     return True
   except ValueError:
    continue
 return False

def integration_records(etl):
 """Accept legacy raw facts or the typed ``sources.json`` catalog."""
 if 'facts' in etl:
  return [f for f in etl['facts'] if f.get('field')=='source_integration'
          and f.get('evidence_status') in ('vendor_catalog','vendor_table')]
 rows=etl.get('items',etl.get('integrations',[]))
 result=[]
 for row in rows:
  evidence=(row.get('evidence') or [{}])[0]
  result.append({'siem_id':row['siem_id'],'value':row['source_name'],
                 'source_entity_id':row.get('source_entity_id'),
                 'source_vendor':row.get('source_vendor'),
                 'source_version':row.get('source_version'),
                 'source_url':evidence.get('url'),'product_version_hint':row.get('siem_version_hint'),
                 'normalizer_id':row.get('normalizer_id'),'collection_method':row.get('collection_method'),
                 'source_variant':row.get('source_variant'),
                 'support_scope':row.get('support_scope')})
 return result

def evaluate(vendors,etl,infra, reviewed_deployment_rules=None):
 if infra.get('default_custom_parser_rub',0)<0: raise ValueError('Стоимость парсера должна быть >=0')
 by_vendor={}
 records=integration_records(etl)
 for fact in records:
  key=fact.get('source_entity_id') or canonical(fact['value'])
  by_vendor.setdefault(fact['siem_id'],{}).setdefault(key.removeprefix('source:'),[]).append(fact)
 # A variant can be used without the family prefix only if unique for this SIEM.
 # E.g. "1С Зарплата и управление персоналом" -> 1С:ЗУП; however "Switch"
 # appears under several hardware vendors, and must never match by itself.
 variants=[f for f in records if f.get('source_variant')]
 seen_variants=Counter((f['siem_id'],canonical(f['source_variant'])) for f in variants)
 for fact in variants:
  alias=canonical(fact['source_variant'])
  if len(alias)>=5 and seen_variants[(fact['siem_id'],alias)]==1:
   by_vendor.setdefault(fact['siem_id'],{}).setdefault(alias,[]).append(fact)
 needs=infra['event_sources']; outcome=[]
 reviewed_deployment_rules=reviewed_deployment_rules or []
 source_total=sum(float(s.get('criticality',1)) for s in needs)
 if source_total<=0:raise ValueError('Нужен хотя бы один источник с положительной важностью')
 for vendor in vendors:
  available=by_vendor.get(vendor['id'],{})
  # Include explicit vendor + product names from structured docs (no arbitrary fuzzy match).
  for fact in records:
   if fact.get('siem_id')==vendor['id'] and fact.get('source_vendor'):
    available.setdefault(canonical(fact['source_vendor']+' '+fact['value']),[]).append(fact)
  rows=[]; weighted=0; cost=0; unknown=0; documented_count=0
  for src in needs:
   title=src['name'];criticality=float(src.get('criticality',1))
   if criticality<0:raise ValueError('criticality >= 0')
   exact=available.get(canonical(title),[])
   # A record can be reachable through both its typed identity and its unique
   # variant alias.  It remains one published claim and one evidence item.
   seen_records=set()
   unique_exact=[]
   for fact in exact:
    if id(fact) not in seen_records:
     seen_records.add(id(fact))
     unique_exact.append(fact)
   exact=unique_exact
   # Family/cousin names do not constitute a supported edition/variant.
   # A listed source may be documented for a DIFFERENT version. Do not silently accept.
   asked_version=str(src.get('version','')).strip()
   full=[f for f in exact if f.get('support_scope') != 'partial']
   if exact and not full:
    status='published_partial_support_requires_confirmation';factor=0.60;unknown+=1
    estimated=float(src.get('partial_support_check_rub',src.get('version_check_rub',0)));evidence=[]
   elif full and asked_version and not any(_version_matches(asked_version, f.get('source_version')) for f in full):
    status='source_version_requires_confirmation';factor=0.60;unknown+=1
    estimated=float(src.get('version_check_rub',0));evidence=[]
   elif full:
    documented_count+=1
    status='published_integration';factor=0.85;estimated=0
    evidence=[{'url':f['source_url'],'version_scope':f.get('source_version'),
               'siem_version_hint':f.get('product_version_hint'), 'normalizer_id':f.get('normalizer_id'),
               'collection_method':f.get('collection_method')} for f in full[:3]]
   else:
    status='not_documented_needs_review';factor=0.45;unknown+=1
    estimated=float(src.get('custom_parser_rub',infra.get('default_custom_parser_rub',0)))
    evidence=[]
   weighted+=factor*criticality;cost+=estimated
   rows.append({'event_source':title,'match_status':status,'readiness_factor':factor,
                'estimated_integration_rub':round(estimated,2),
                'assumption':'Оценка заказчика; требует уточнения у вендора' if estimated else None,
                'evidence':evidence})
  # Candidate architecture facts are NOT auto-interpreted as deployment requirements.
  arch_candidates=[f for f in etl.get('facts',[]) if f['siem_id']==vendor['id'] and f['field'] in ('deployment','dependencies','resources')][:8]
  integration_fit=round(100*weighted/source_total,2)
  # Scoring uses ONLY explicitly reviewed, version-scoped architecture rules.
  # Product marketing descriptions/candidate evidence never force Kubernetes or extra servers.
  deploy_work=[];deploy_cost=0.0
  environment=infra.get('environment',{})
  for rule in reviewed_deployment_rules:
   if rule.get('siem_id')!=vendor['id'] or rule.get('approval_status')!='approved': continue
   target_version=rule.get('product_version')
   if not target_version or not rule.get('source_url'): continue
   key=rule.get('requirement')
   if key=='kubernetes' and not environment.get('kubernetes_available',False):
    price=float(environment.get('kubernetes_setup_rub',0))
    deploy_cost+=price
    deploy_work.append({'requirement':'kubernetes','estimated_rub':price,'source_url':rule['source_url'],'product_version':target_version})
   elif key=='additional_server' and float(environment.get('available_server_capacity',0)) < float(rule.get('min_free_capacity',1)):
    price=float(environment.get('additional_server_rub',0))
    deploy_cost+=price
    deploy_work.append({'requirement':'additional_server','estimated_rub':price,'source_url':rule['source_url'],'product_version':target_version})
  total_estimated=cost+deploy_cost
  budget=infra.get('budget_rub')
  overrun=max(0,total_estimated-float(budget)) if budget is not None else None
  # No vendor integration evidence means unknown, not an invented 45/100 rating.
  if documented_count==0:
   integration_fit=None
  # score is heuristic and explicit; not reliability probability or final MCDA.
  if overrun and budget is not None:
   budget_penalty=25 if float(budget)<=0 else min(25,100*overrun/float(budget))
  else: budget_penalty=0
  score=max(0,round(integration_fit-budget_penalty,2)) if integration_fit is not None else None
  outcome.append({'siem_id':vendor['id'],'siem_name':vendor['name'],
   'integration_fit_score_0_100':integration_fit,'conditional_fit_score_0_100':score,
   'assessment_status':('insufficient_evidence' if documented_count==0 else 'partial_evidence'),
   'documented_source_matches':documented_count,
   'estimated_extra_cost_rub':round(total_estimated,2),'estimated_parser_cost_rub':round(cost,2),'budget_overrun_estimate_rub':round(overrun,2) if overrun is not None else None,
   'unknown_integrations':unknown,'infrastructure_changes_estimate_rub':round(deploy_cost,2) if deploy_work else None,'deployment_actions':deploy_work,
   'deploy_requirements_review_candidates':[{k:f.get(k) for k in ('field','value','source_url','product_version_hint','evidence_excerpt')} for f in arch_candidates],
   'source_assessments':rows,
   'warning':'Условный показатель: не учитывает лицензии, подтверждённый sizing, стоимость инфраструктуры, техническую проверку интеграций.'})
 return sorted(outcome,key=lambda r:(r['conditional_fit_score_0_100'] is None,-(r['conditional_fit_score_0_100'] or 0),r['siem_id']))
