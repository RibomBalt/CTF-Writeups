# from chall import *
import ast

BANNED = {
    #def not
    ast.Import,
    ast.ImportFrom,
    ast.With,
    ast.alias,
    ast.Attribute,
    ast.Constant,

    #should be fine?
    ast.Subscript,
    ast.Assign,
    ast.AnnAssign,
    ast.AugAssign,
    ast.For,
    ast.Try,
    ast.ExceptHandler,
    ast.With,
    ast.withitem,
    ast.FunctionDef,
    ast.Lambda,
    ast.ClassDef,


    #prob overkill but should be fine
    ast.If,
    ast.And,
    ast.comprehension,
    ast.In,
    ast.Await,
    ast.Global,
    ast.Gt,
    ast.ListComp,
    ast.Slice,
    ast.Return,
    ast.List,
    ast.Dict,
    ast.Lt,
    ast.AsyncFunctionDef,
    ast.Eq,
    ast.keyword,
    ast.Mult,
    ast.arguments,
    ast.FormattedValue,
    ast.Not,
    ast.BoolOp,
    ast.Or,
    ast.Compare,
    ast.GtE,
    ast.ImportFrom,
    ast.Tuple,
    ast.NotEq,
    ast.IfExp,
    ast.alias,
    ast.arg,
    ast.JoinedStr,

    # Patch some more >:)
    ast.Match, 
    ast.Del,
    ast.Starred,
    ast.Is,
    ast.NamedExpr,
}

all_ast = set([s for s in dir(ast)]).difference(set([b.__name__ for b in BANNED]))
print(all_ast)

'''
dict_keys(['__name__', '__doc__', '__package__', '__loader__', '__spec__', '__build_class__', '__import__', 'abs', 'ascii', 'bin', 'chr', 'delattr', 'divmod', 'format', 'getattr', 'hasattr', 'hash', 'hex', 'id', 'isinstance', 'issubclass', 'iter', 'aiter', 'len', 'locals', 'max', 'min', 'next', 'anext', 'oct', 'ord', 'pow', 'repr', 'round', 'setattr', 'sorted', 'sum', 'vars', 'None', 'Ellipsis', 'NotImplemented', 'False', 'True', 'bool', 'memoryview', 'bytearray', 'bytes', 'classmethod', 'complex', 'dict', 'enumerate', 'filter', 'float', 'frozenset', 'property', 'list', 'map', 'object', 'range', 'reversed', 'set', 'slice', 'staticmethod', 'str', 'super', 'tuple', 'zip', '__debug__', 'BaseException', 'BaseExceptionGroup', 'Exception', 'GeneratorExit', 'KeyboardInterrupt', 'SystemExit', 'ArithmeticError', 'AssertionError', 'AttributeError', 'BufferError', 'EOFError', 'ImportError', 'LookupError', 'MemoryError', 'NameError', 'OSError', 'ReferenceError', 'RuntimeError', 'StopAsyncIteration', 'StopIteration', 'SyntaxError', 'SystemError', 'TypeError', 'ValueError', 'Warning', 'FloatingPointError', 'OverflowError', 'ZeroDivisionError', 'BytesWarning', 'DeprecationWarning', 'EncodingWarning', 'FutureWarning', 'ImportWarning', 'PendingDeprecationWarning', 'ResourceWarning', 'RuntimeWarning', 'SyntaxWarning', 'UnicodeWarning', 'UserWarning', 'BlockingIOError', 'ChildProcessError', 'ConnectionError', 'FileExistsError', 'FileNotFoundError', 'InterruptedError', 'IsADirectoryError', 'NotADirectoryError', 'PermissionError', 'ProcessLookupError', 'TimeoutError', 'IndentationError', 'IndexError', 'KeyError', 'ModuleNotFoundError', 'NotImplementedError', 'RecursionError', 'UnboundLocalError', 'UnicodeError', 'BrokenPipeError', 'ConnectionAbortedError', 'ConnectionRefusedError', 'ConnectionResetError', 'TabError', 'UnicodeDecodeError', 'UnicodeEncodeError', 'UnicodeTranslateError', 'ExceptionGroup', 'EnvironmentError', 'IOError', 'open', '_'])
'''