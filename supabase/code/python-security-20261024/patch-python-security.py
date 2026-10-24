# Minimal upstream-compatible security backport for immutable container images.
# Reference: CPython gh-156793 / 966bf426d0b6c31c1b0a255ff14a17143a466ced.
import pathlib,sys,ssl,re,hashlib,json,argparse,importlib.util,py_compile,shutil,ast
parser=argparse.ArgumentParser();parser.add_argument('--pip-wheel');args=parser.parse_args();changes={}
ctx=ssl.create_default_context()
try:ctx.wrap_bio(ssl.MemoryBIO(),ssl.MemoryBIO(),server_hostname=None)
except ValueError:needs_guard=False
else:needs_guard=True
if needs_guard:
 p=pathlib.Path(ssl.__file__);source=p.read_text();tree=ast.parse(source);cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='SSLObject');method=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='_create');assert {'context','server_side','server_hostname','session'}.issubset({n.arg for n in method.args.args});statements=method.body;first=statements[1] if isinstance(statements[0],ast.Expr) and isinstance(statements[0].value,ast.Constant) and isinstance(statements[0].value.value,str) else statements[0];assert first.col_offset==8;body=sum(len(line) for line in source.splitlines(keepends=True)[:first.lineno-1])
 guard='''
        # Backport CPython gh-156793: match wrap_socket argument validation.
        if server_side:
            if server_hostname:
                raise ValueError("server_hostname can only be specified in client mode")
            if session is not None:
                raise ValueError("session can only be specified in client mode")
        if context.check_hostname and not server_hostname:
            raise ValueError("check_hostname requires server_hostname")
'''
 old=hashlib.sha256(source.encode()).hexdigest();source=source[:body]+guard.lstrip('\n')+source[body:]
 compile(source,str(p),'exec');p.write_text(source)
 for cache in (p.parent/'__pycache__').glob('ssl.*.pyc'):cache.unlink()
 for level in [0,1,2]:py_compile.compile(str(p),doraise=True,optimize=level)
 changes['sslGuard']={'beforeSha256':old,'afterSha256':hashlib.sha256(source.encode()).hexdigest()}
if importlib.util.find_spec('ensurepip'):
 import ensurepip
 current=tuple(int(x) for x in ensurepip.version().split('.'))
 if current<(26,2,2):
  assert args.pip_wheel,'A verified replacement pip wheel is required';wheel=pathlib.Path(args.pip_wheel);assert hashlib.file_digest(open(wheel,'rb'),'sha256').hexdigest()=='fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70'
  p=pathlib.Path(ensurepip.__file__);source=p.read_text();source,count=re.subn(r'(?m)^_PIP_VERSION\s*=\s*[\'"][^\'"]+[\'"]', '_PIP_VERSION = "26.2.2"',source);assert count==1,'Unexpected ensurepip version configuration';p.write_text(source);folders={p.parent/'_bundled'};external=getattr(ensurepip,'_WHEEL_PKG_DIR',None)
  if external:folders.add(pathlib.Path(external))
  for folder in folders:
   assert str(folder).startswith(('/usr/lib/','/usr/share/','/opt/')),'Unexpected wheel directory';folder.mkdir(parents=True,exist_ok=True)
   for old in folder.glob('pip-*.whl'):old.unlink()
   shutil.copy2(wheel,folder/'pip-26.2.2-py3-none-any.whl')
  for cache in (p.parent/'__pycache__').glob('__init__.*.pyc'):cache.unlink()
  for level in [0,1,2]:py_compile.compile(str(p),doraise=True,optimize=level)
  changes['ensurepip']={'before':'.'.join(map(str,current)),'after':'26.2.2','wheelSha256':'fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70'}
out=pathlib.Path('/usr/local/share/trafficlion');out.mkdir(parents=True,exist_ok=True);(out/'python-security-backports.json').write_text(json.dumps(changes,indent=2));print(json.dumps({'pythonSecurityBackports':changes}))
