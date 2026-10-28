from __future__ import annotations
import math

def normalize(raw, criteria):
    """Context-independent min/max normalisation across available alternatives."""
    out = {p['id']: {} for p in raw}
    for c in criteria:
        key = c['id']
        xs = [float(p['raw'][key]) for p in raw if isinstance(p['raw'].get(key), (int,float))]
        if len(xs) != len(raw):
            raise ValueError(f'Пропущено или нечисловое значение {key}')
        lo,hi = min(xs),max(xs)
        for p in raw:
            v=float(p['raw'][key]); out[p['id']][key] = (hi-v)/(hi-lo) if c['kind']=='cost' and hi>lo else ((v-lo)/(hi-lo) if hi>lo else 1.0)
    return out

def weighted_sum(ids, normalized, weights):
    if not weights or sum(weights.values()) <= 0 or any(v<0 for v in weights.values()):
        raise ValueError('Некорректные веса')
    den=sum(weights.values())
    return {pid:100*sum(weights[k]*normalized[pid][k] for k in weights)/den for pid in ids}

def topsis(ids, normalized, weights):
    if not ids: return {}
    if not weights or sum(weights.values())<=0 or any(v<0 for v in weights.values()): raise ValueError('Некорректные веса')
    den=sum(weights.values())
    # Benefit-oriented normalized matrix; TOPSIS vector normalisation for each criterion.
    columns={k:math.sqrt(sum(normalized[pid][k]**2 for pid in ids)) for k in weights}
    weighted={pid:{k:weights[k]/den*normalized[pid][k]/(columns[k] or 1.0) for k in weights} for pid in ids}
    ideal={k:max(weighted[pid][k] for pid in ids) for k in weights}
    anti={k:min(weighted[pid][k] for pid in ids) for k in weights}
    scores={}
    for pid in ids:
        positive=math.sqrt(sum((weighted[pid][k]-ideal[k])**2 for k in weights))
        negative=math.sqrt(sum((weighted[pid][k]-anti[k])**2 for k in weights))
        scores[pid]=100*negative/(positive+negative) if positive+negative>0 else 50.0
    return scores

def estimate_eps(infra):
    """Sum event rates using quantities and EPS per unit; peak multiplier and headroom."""
    sources=infra['sources']; details=[]; base=0.0
    for x in sources:
        count=float(x['count']); rate=float(x['eps_per_unit'])
        if count < 0 or rate<0: raise ValueError('Количество и EPS не могут быть отрицательными')
        eps=count*rate; base+=eps; details.append({'type':x['type'],'quantity':count,'eps_per_unit':rate,'eps':round(eps,2)})
    peak=float(infra.get('peak_multiplier',1)); reserve=float(infra.get('reserve_pct',0))
    if peak<1 or reserve<0:raise ValueError('Некорректный пик или резерв')
    return {'sources':details,'base_eps':round(base,2),'peak_eps':round(base*peak,2),'required_eps':math.ceil(base*peak*(1+reserve/100))}

def analyze(catalog,infra,method='wsm',weights=None,epsilon=0.25):
    if method not in ('wsm','topsis'):raise ValueError('Неизвестный метод')
    eps=estimate_eps(infra); criteria=catalog['criteria']; products=catalog['products']
    weights=weights or {c['id']:float(c['weight']) for c in criteria}
    missing=set(weights)-{c['id'] for c in criteria}
    if missing:raise ValueError('Неизвестные критерии: '+str(missing))
    # Use the original spreadsheet's normalized matrix for reproducibility; all 15 columns kept.
    matrix={p['id']:p['normalized_source'] for p in products}
    eligible=[]; excluded=[]
    for p in products:
        reasons=[]; extra=[]
        quoted_price=p['raw'].get('c01')
        # Original offer is not a confirmed TCO; price constraint is therefore an advisory rule.
        if infra.get('budget_million') is not None and isinstance(quoted_price,(int,float)) and quoted_price>infra['budget_million']:
            reasons.append('Исходное КП превышает бюджет (предварительный фильтр, не TCO)')
        tariff=p['raw'].get('c02')
        if isinstance(tariff,(int,float)) and tariff<eps['required_eps']:
            extra.append('EPS-тариф в таблице ниже расчетной потребности; требуется проверка масштабирования/изменения тарифа')
        if infra.get('critical_infrastructure'):
            extra.append('КИИ: необходимо отдельно проверить применимые требования и действительность сертификатов')
        if infra.get('fstek_required'):
            extra.append('ФСТЭК: в числовом листе нет достоверного бинарного признака действующего сертификата')
        if infra.get('required_sources'):
            extra.append('Точное покрытие источников не подтверждено количественным листом; требуется сверка с каталогом интеграций')
        if reasons:excluded.append({'id':p['id'],'name':p['name'],'reasons':reasons,'warnings':extra})
        else:eligible.append(p)
        p['_warnings']=extra
    ids=[p['id'] for p in eligible]
    scores=(weighted_sum(ids,matrix,weights) if method=='wsm' else topsis(ids,matrix,weights))
    ranking=sorted([{'id':p['id'],'name':p['name'],'score':round(scores[p['id']],3),'warnings':p['_warnings']} for p in eligible],key=lambda p:(-p['score'],p['name']))
    return {'method':method,'eps':eps,'ranking':ranking,'excluded':excluded,'limitations':['Результат основан на историческом авторском снимке данных; без верификации нельзя считать его рекомендацией к закупке.','Покрытие конкретных типов источников и действительность сертификатов требуют дополнительного справочника.','Цена исходного КП не равна TCO; стоимость новых коннекторов и внедрения пока не рассчитывается.']}

def sensitivity(catalog,infra,method='wsm',runs=200,relative_change=0.25,seed=42):
    if runs<1:raise ValueError('runs должен быть положительным')
    rng=__import__('random').Random(seed)
    base={c['id']:float(c['weight']) for c in catalog['criteria']}
    wins={p['id']:0 for p in catalog['products']}
    for _ in range(runs):
        weights={k:v*rng.uniform(1-relative_change,1+relative_change) for k,v in base.items()}
        outcome=analyze(catalog,infra,method,weights)
        if outcome['ranking']:wins[outcome['ranking'][0]['id']]+=1
    return {k:round(v/runs,4) for k,v in wins.items()}
