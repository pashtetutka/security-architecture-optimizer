import argparse,json
from pathlib import Path
from siem.core import analyze,sensitivity

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--catalog',default='data/reference_metrics.json')
    p.add_argument('--infra',default='data/demo_infra.json')
    p.add_argument('--method',choices=['wsm','topsis'],default='wsm')
    p.add_argument('--sensitivity',type=int,default=0)
    args=p.parse_args()
    cat=json.loads(Path(args.catalog).read_text(encoding='utf8')); infra=json.loads(Path(args.infra).read_text(encoding='utf8'))
    result=analyze(cat,infra,args.method)
    if args.sensitivity: result['sensitivity_top1']=sensitivity(cat,infra,args.method,args.sensitivity)
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
