"""Веб-интерфейс: pip install streamlit pandas; streamlit run app.py."""
import json
from pathlib import Path
import streamlit as st
import pandas as pd
from siem.core import analyze,sensitivity
st.set_page_config(page_title='SIEM Decision Support',layout='wide')
st.title('Поддержка выбора SIEM')
st.caption('Исследовательский прототип. Исторические оценки не равны текущим характеристикам продуктов.')
catalog=json.loads(Path('data/reference_metrics.json').read_text(encoding='utf8'))
with st.sidebar:
    st.header('Опросный лист')
    budget=st.number_input('Бюджет, млн руб. (0 — без фильтра)',min_value=0.0,value=5.0,step=0.5)
    kii=st.checkbox('Объект КИИ')
    fstek=st.checkbox('Требуется сертификат ФСТЭК')
    peak=st.number_input('Пиковый множитель',min_value=1.0,value=1.5,step=0.1)
    reserve=st.number_input('Резерв по EPS, %',min_value=0,value=20)
    method=st.selectbox('Метод', ['wsm','topsis'],format_func=lambda x: {'wsm':'Взвешенная сумма','topsis':'TOPSIS'}[x])
    change=st.slider('Разброс весов при анализе чувствительности, %',0,70,25)
    runs=st.slider('Число экспериментов',50,500,200,50)
st.subheader('Источники событий')
initial=json.loads(Path('data/demo_infra.json').read_text(encoding='utf8'))['sources']
rows=st.data_editor(pd.DataFrame(initial),num_rows='dynamic',use_container_width=True)
source_types=st.text_input('Обязательные типы источников (через запятую)','Windows,Linux,NGFW')
infra={'budget_million':budget or None,'critical_infrastructure':kii,'fstek_required':fstek,'peak_multiplier':peak,'reserve_pct':reserve,'required_sources':[x.strip() for x in source_types.split(',') if x.strip()],'sources':rows.to_dict('records')}
if st.button('Рассчитать',type='primary'):
    try:
        result=analyze(catalog,infra,method)
        st.metric('Расчётная потребность',f"{result['eps']['required_eps']} EPS")
        st.write('Нагрузка по типам источников');st.dataframe(pd.DataFrame(result['eps']['sources']),use_container_width=True)
        st.subheader('Ранжирование');rank=pd.DataFrame(result['ranking'])
        st.dataframe(rank,use_container_width=True)
        if not rank.empty: st.bar_chart(rank.set_index('name')['score'])
        st.subheader('Устойчивость первого места к изменению весов')
        sens=sensitivity(catalog,infra,method,runs,change/100)
        label={p['id']:p['name'] for p in catalog['products']}
        st.bar_chart(pd.DataFrame([{'name':label[k],'share':v} for k,v in sens.items()]).set_index('name'))
        st.subheader('Исключения');st.dataframe(pd.DataFrame(result['excluded']),use_container_width=True)
        st.warning(' '.join(result['limitations']))
        st.download_button('Скачать результат JSON',json.dumps({'input':infra,'result':result},ensure_ascii=False,indent=2),'siem_result.json')
    except (ValueError,KeyError,TypeError) as e:st.error(str(e))
