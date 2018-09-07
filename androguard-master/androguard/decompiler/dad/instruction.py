# This file is part of Androguard.
#
# Copyright (c) 2012 Geoffroy Gueguen <geoffroy.gueguen@gmail.com>
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


class IRForm(object):
    def __init__(self):
        self.var_map = {}
        self.type = None

    def is_call(self):
        return False

    def is_cond(self):
        return False

    def is_const(self):
        return False

    def is_ident(self):
        return False

    def is_propagable(self):
        return True

    def get_type(self):
        return None

    def has_side_effect(self):
        return False

    def get_used_vars(self):
        return []

    def modify_rhs(self, old, new):
        if old in self.var_map:
            self.var_map[old] = new
        else:
            import logging
            logger = logging.getLogger('dad.instruction')
            logger.error('modify_rhs not implemented %s', self)

    def remove_defined_var(self):
        pass

    def get_rhs(self):
        return []

    def get_lhs(self):
        return None

    def visit(self, visitor):
        pass


class Constant(IRForm):
    def __init__(self, value, atype, int_value=None):
        self.v = 'c%s' % value
        self.cst = value
        if int_value is None:
            self.cst2 = value
        else:
            self.cst2 = int_value
        self.type = atype

    def get_used_vars(self):
        return []

    def is_call(self):
        return False

    def is_const(self):
        return True

    def get_int_value(self):
        return self.cst2

    def get_type(self):
        return self.type

    def visit(self, visitor, to_int=False):
        if self.type == 'Z':
            if self.cst == 0:
                return visitor.visit_constant('false')
            else:
                return visitor.visit_constant('true')
        elif self.type == 'class':
            return visitor.visit_base_class(self.cst)
        elif to_int:
            return visitor.visit_constant(self.cst2)
        else:
            return visitor.visit_constant(self.cst)

    def __str__(self):
        return 'CST_%s' % repr(self.cst)


class BaseClass(IRForm):
    def __init__(self, name):
        self.v = 'c%s' % name
        self.cls = name

    def is_const(self):
        return True

    def visit(self, visitor):
        return visitor.visit_base_class(self.cls)

    def __str__(self):
        return 'BASECLASS_%s' % self.cls


class Variable(IRForm):
    def __init__(self, value):
        self.v = value

    def get_type(self):
        return None

    def get_used_vars(self):
        return [self.v]

    def is_call(self):
        return False

    def is_ident(self):
        return True

    def visit(self, visitor):
        return visitor.visit_variable(self.v)

    def visit_decl(self, visitor):
        return visitor.visit_decl(self.v)

    def __str__(self):
        return 'VAR_%s' % self.v


class Param(IRForm):
    def __init__(self, value, atype):
        self.v = value
        self.type = atype

    def get_type(self):
        return self.type

    def get_used_vars(self):
        return [self.v]

    def is_call(self):
        return False

    def is_ident(self):
        return True

    def visit(self, visitor):
        return visitor.visit_param(self.v)

    def visit_decl(self, visitor):
        pass

    def __str__(self):
        return 'PARAM_%s' % self.v


class ThisParam(Param):
    def __init__(self, value, atype):
        super(ThisParam, self).__init__(value, atype)

    def is_const(self):
        return True

    def get_used_vars(self):
        return []

    def is_ident(self):
        return True

    def visit(self, visitor):
        return visitor.visit_this()

    def visit_decl(self, visitor):
        pass

    def __str__(self):
        return 'THIS'


class AssignExpression(IRForm):
    def __init__(self, lhs, rhs):
        super(AssignExpression, self).__init__()
        self.lhs = lhs.v
        self.rhs = rhs
        self.var_map[lhs.v] = lhs

    def is_propagable(self):
        return self.rhs.is_propagable()

    def is_call(self):
        return self.rhs.is_call()

    def has_side_effect(self):
        return self.rhs.has_side_effect()

    def get_rhs(self):
        return self.rhs

    def get_lhs(self):
        return self.lhs

    def get_used_vars(self):
        return self.rhs.get_used_vars()

    def remove_defined_var(self):
        self.lhs = None

    def modify_rhs(self, old, new):
        self.rhs.modify_rhs(old, new)

    def visit(self, visitor):
        return visitor.visit_assign(self.var_map.get(self.lhs), self.rhs)

    def __str__(self):
        return 'ASSIGN(%s, %s)' % (self.var_map.get(self.lhs), self.rhs)


class MoveResultExpression(IRForm):
    def __init__(self, lhs, rhs, type):
        super(MoveResultExpression, self).__init__()
        self.lhs = lhs.v
        self.rhs = rhs.v
        self.var_map.update([(lhs.v, lhs), (rhs.v, rhs)])
        self.type = type

    def is_propagable(self):
        return self.var_map[self.rhs].is_propagable()

    def is_call(self):
        return self.var_map[self.rhs].is_call()

    def has_side_effect(self):
        return self.var_map[self.rhs].has_side_effect()

    def get_used_vars(self):
        return self.var_map[self.rhs].get_used_vars()

    def get_rhs(self):
        return self.var_map[self.rhs]

    def get_lhs(self):
        return self.lhs

    def visit(self, visitor):
        v_m = self.var_map
        return visitor.visit_move_result(v_m[self.lhs], v_m[self.rhs])

    def modify_rhs(self, old, new):
        if old == self.rhs:
            self.var_map[old] = new
        else:
            self.var_map[self.rhs].modify_rhs(old, new)

    def __str__(self):
        v_m = self.var_map
        return '%s = %s' % (v_m.get(self.lhs), v_m.get(self.rhs))


class MoveExpression(IRForm):
    def __init__(self, lhs, rhs):
        super(MoveExpression, self).__init__()
        self.lhs = lhs.v
        self.rhs = rhs.v
        self.var_map.update([(lhs.v, lhs), (rhs.v, rhs)])

    def has_side_effect(self):
        return False

    def is_call(self):
        return self.var_map[self.rhs].is_call()

    def get_used_vars(self):
        return self.var_map[self.rhs].get_used_vars()

    def get_rhs(self):
        return self.var_map[self.rhs]

    def get_lhs(self):
        return self.lhs

    def visit(self, visitor):
        v_m = self.var_map
        return visitor.visit_move(v_m[self.lhs], v_m[self.rhs])

    def modify_rhs(self, old, new):
        if old == self.rhs:
            self.var_map[old] = new
        else:
            rhs = self.var_map[self.rhs]
            if not (rhs.is_const() or rhs.is_ident()):
                rhs.modify_rhs(old, new)

    def __str__(self):
        v_m = self.var_map
        return '%s = %s' % (v_m.get(self.lhs), v_m.get(self.rhs))


class ArrayStoreInstruction(IRForm):
    def __init__(self, rhs, array, index, type):
        super(ArrayStoreInstruction, self).__init__()
        self.rhs = rhs.v
        self.array = array.v
        self.index = index.v
        self.var_map.update([(rhs.v, rhs), (array.v, array), (index.v, index)])
        self.type = type

    def has_side_effect(self):
        return True

    def get_used_vars(self):
        v_m = self.var_map
        lused_vars = v_m[self.array].get_used_vars()
        lused_vars.extend(v_m[self.index].get_used_vars())
        lused_vars.extend(v_m[self.rhs].get_used_vars())
        return list(set(lused_vars))

    def visit(self, visitor):
        v_m = self.var_map
        return visitor.visit_astore(v_m[self.array],
                                    v_m[self.index], v_m[self.rhs])

    def modify_rhs(self, old, new):
        if old in self.var_map:
            self.var_map[old] = new
        else:
            arr = self.var_map[self.array]
            idx = self.var_map[self.index]
            rhs = self.var_map[self.rhs]
            for arg in (arr, idx, rhs):
                if not (arg.is_const() or arg.is_ident()):
                    arg.modify_rhs(old, new)

    def __str__(self):
        v_m = self.var_map
        arr = v_m[self.array]
        idx = v_m[self.index]
        rhs = v_m[self.rhs]
        return '%s[%s] = %s' % (arr, idx, rhs)


class StaticInstruction(IRForm):
    def __init__(self, rhs, klass, ftype, name):
        super(StaticInstruction, self).__init__()
        self.rhs = rhs.v
        self.cls = klass
        self.ftype = ftype
        self.name = name
        self.var_map[rhs.v] = rhs

    def has_side_effect(self):
        return True

    def get_used_vars(self):
        return self.var_map[self.rhs].get_used_vars()

    def get_lhs(self):
        return None

    def visit(self, visitor):
        v_m = self.var_map
        return visitor.visit_put_static(self.cls, self.name, v_m[self.rhs])

    def modify_rhs(self, old, new):
        if old in self.var_map:
            self.var_map[old] = new
        else:
            self.var_map[self.rhs].modify_rhs(old, new)


class InstanceInstruction(IRForm):
    def __init__(self, rhs, lhs, klass, atype, name):
        super(InstanceInstruction, self).__init__()
        self.lhs = lhs.v
        self.rhs = rhs.v
        self.atype = atype
        self.cls = klass
        self.name = name
        self.var_map.update([(lhs.v, lhs), (rhs.v, rhs)])

    def has_side_effect(self):
        return True

    def get_used_vars(self):
        v_m = self.var_map
        lused_vars = v_m[self.lhs].get_used_vars()
        lused_vars.extend(v_m[self.rhs].get_used_vars())
        return list(set(lused_vars))

    def get_lhs(self):
        return None

    def visit(self, visitor):
        v_m = self.var_map
        return visitor.visit_put_instance(v_m[self.lhs],
                                          self.name, v_m[self.rhs])

    def modify_rhs(self, old, new):
        v_m = self.var_map
        if old in v_m:
            v_m[old] = new
        else:
            lhs = v_m[self.lhs]
            rhs = v_m[self.rhs]
            for arg in (lhs, rhs):
                if not (arg.is_const() or arg.is_ident()):
                    arg.modify_rhs(old, new)

    def __str__(self):
        v_m = self.var_map
        return '%s.%s = %s' % (v_m[self.lhs], self.name, v_m[self.rhs])


class NewInstance(IRForm):
    def __init__(self, ins_type):
        super(NewInstance, self).__init__()
        self.type = ins_type

    def get_type(self):
        return self.type

    def get_used_vars(self):
        return []

    def visit(self, visitor):
        return visitor.visit_new(self.type)

    def modify_rhs(self, old, new):
        pass

    def __str__(self):
        return 'NEW(%s)' % self.type


class InvokeInstruction(IRForm):
    def __init__(self, clsname, name, base, rtype, ptype, args):
        super(InvokeInstruction, self).__init__()
        self.cls = clsname
        self.name = name
        self.base = base.v
        self.rtype = rtype
        self.ptype = ptype
        self.args = [arg.v for arg in args]
        self.var_map[base.v] = base
        for arg in args:
            self.var_map[arg.v] = arg

    def get_type(self):
        return self.rtype

    def is_call(self):
        return True

    def has_side_effect(self):
        return True

    def modify_rhs(self, old, new):
        if old in self.var_map:
            arg = self.var_map[old]
            if not (arg.is_ident() or arg.is_const()):
                arg.modify_rhs(old, new)
            else:
                self.var_map[old] = new
        else:
            base = self.var_map[self.base]
            if not (base.is_ident() or base.is_const()):
                base.modify_rhs(old, new)
            for arg in self.args:
                cnt = self.var_map[arg]
                if cnt.is_ident() or cnt.is_const():
                    continue
                else:
                    self.var_map[arg].modify_rhs(old, new)

    def get_used_vars(self):
        v_m = self.var_map
        lused_vars = []
        for arg in self.args:
            lused_vars.extend(v_m[arg].get_used_vars())
        lused_vars.extend(v_m[self.base].get_used_vars())
        return list(set(lused_vars))

    def visit(self, visitor):
        v_m = self.var_map
        largs = [v_m[arg] for arg in self.args]
        return visitor.visit_invoke(self.name, v_m[self.base], self.rtype,
                                    self.ptype, largs)

    def __str__(self):
        v_m = self.var_map
        return '%s.%s(%s)' % (v_m[self.base], self.name,
                                ', '.join(str(v_m[i]) for i in self.args))


class InvokeRangeInstruction(InvokeInstruction):
    def __init__(self, clsname, name, rtype, ptype, args):
        base = args.pop(0)
        super(InvokeRangeInstruction, self).__init__(clsname, name, base,
                                                    rtype, ptype, args)


class InvokeDirectInstruction(InvokeInstruction):
    def __init__(self, clsname, name, base, rtype, ptype, args):
        super(InvokeDirectInstruction, self).__init__(clsname, name, base,
                                                    rtype, ptype, args)


class InvokeStaticInstruction(InvokeInstruction):
    def __init__(self, clsname, name, base, rtype, ptype, args):
        # TODO: check base class name and current class name
        super(InvokeStaticInstruction, self).__init__(clsname, name, base,
                                                    rtype, ptype, args)

    def get_used_vars(self):
        v_m = self.var_map
        lused_vars = []
        for arg in self.args:
            lused_vars.extend(v_m[arg].get_used_vars())
        return list(set(lused_vars))


class ReturnInstruction(IRForm):
    def __init__(self, arg):
        super(ReturnInstruction, self).__init__()
        self.arg = arg
        if arg is not None:
            self.var_map[arg.v] = arg
            self.arg = arg.v

    def get_used_vars(self):
        if self.arg is None:
            return []
        return self.var_map[self.arg].get_used_vars()

    def get_lhs(self):
        return None

    def visit(self, visitor):
        if self.arg is None:
            return visitor.visit_return_void()
        else:
            return visitor.visit_return(self.var_map[self.arg])

    def modify_rhs(self, old, new):
        arg = self.var_map[self.arg]
        if not (arg.is_const() or arg.is_ident()):
            arg.modify_rhs(old, new)
        else:
            self.var_map[old] = new

    def __str__(self):
        if self.arg is not None:
            return 'RETURN(%s)' % self.var_map.get(self.arg)
        return 'RETURN'


class NopExpression(IRForm):
    def __init__(self):
        pass

    def get_used_vars(self):
        return []

    def get_lhs(self):
        return None

    def visit(self, visitor):
        return visitor.visit_nop()


class SwitchExpression(IRForm):
    def __init__(self, src, branch):
        super(SwitchExpression, self).__init__()
        self.src = src.v
        self.branch = branch
        self.var_map[src.v] = src

    def get_used_vars(self):
        return self.var_map[self.src].get_used_vars()

    def visit(self, visitor):
        return visitor.visit_switch(self.var_map[self.src])

    def modify_rhs(self, old, new):
        if old in self.var_map:
            self.var_map[old] = new
        else:
            src = self.var_map[self.src]
            if not (src.is_const() or src.is_ident()):
                src.modify_rhs(old, new)

    def __str__(self):
        return 'SWITCH(%s)' % (self.var_map[self.src])


class CheckCastExpression(IRForm):
    def __init__(self, arg, _type):
        super(CheckCastExpression, self).__init__()
        self.arg = arg.v
        self.var_map[arg.v] = arg
        self.type = _type

    def get_used_vars(self):
        return self.var_map[self.arg].get_used_vars()

    def visit(self, visitor):
        return visitor.visit_check_cast(self.var_map[self.arg], self.type)

    def modify_rhs(self, old, new):
        if old in self.var_map:
            self.var_map[old] = new
        else:
            arg = self.var_map[self.arg]
            if not (arg.is_const() or arg.is_ident()):
                arg.modify_rhs(old, new)


class ArrayExpression(IRForm):
    def __init__(self):
        super(ArrayExpression, self).__init__()


class ArrayLoadExpression(ArrayExpression):
    def __init__(self, arg, index, type):
        super(ArrayLoadExpression, self).__init__()
        self.array = arg.v
        self.idx = index.v
        self.var_map.update([(arg.v, arg), (index.v, index)])
        self.type = type

    def get_used_vars(self):
        v_m = self.var_map
        lused_vars = v_m[self.array].get_used_vars()
        lused_vars.extend(v_m[self.idx].get_used_vars())
        return list(set(lused_vars))

    def visit(self, visitor):
        v_m = self.var_map
        return visitor.visit_aload(v_m[self.array], v_m[self.idx])

    def modify_rhs(self, old, new):
        if old in self.var_map:
            self.var_map[old] = new
        else:
            arr = self.var_map[self.array]
            idx = self.var_map[self.idx]
            for arg in (arr, idx):
                if not (arg.is_const() or arg.is_ident()):
                    arg.modify_rhs(old, new)

    def __str__(self):
        v_m = self.var_map
        return 'ARRAYLOAD(%s, %s)' % (v_m[self.array], v_m[self.idx])


class ArrayLengthExpression(ArrayExpression):
    def __init__(self, array):
        super(ArrayLengthExpression, self).__init__()
        self.array = array.v
        self.var_map[array.v] = array

    def get_type(self):
        return 'I'

    def get_used_vars(self):
        return self.var_map[self.array].get_used_vars()

    def visit(self, visitor):
        return visitor.visit_alength(self.var_map[self.array])

    def modify_rhs(self, old, new):
        if old in self.var_map:
            self.var_map[old] = new
        else:
            arr = self.var_map[self.array]
            if not (arr.is_const() or arr.is_ident()):
                arr.modify_rhs(old, new)

    def __str__(self):
        return 'ARRAYLEN(%s)' % (self.var_map[self.array])


class NewArrayExpression(ArrayExpression):
    def __init__(self, asize, atype):
        super(NewArrayExpression, self).__init__()
        self.size = asize.v
        self.type = atype
        self.var_map[asize.v] = asize

    def is_propagable(self):
        return False

    def get_used_vars(self):
        return self.var_map[self.size].get_used_vars()

    def visit(self, visitor):
        return visitor.visit_new_array(self.type, self.var_map[self.size])

    def modify_rhs(self, old, new):
        if old in self.var_map:
            self.var_map[old] = new
        else:
            asize = self.var_map[self.size]
            if not (asize.is_const() or asize.is_ident()):
                asize.modify_rhs(old, new)

    def __str__(self):
        return 'NEWARRAY_%s[%s]' % (self.type, self.var_map[self.size])


class FilledArrayExpression(ArrayExpression):
    def __init__(self, asize, atype, args):
        super(FilledArrayExpression, self).__init__()
        self.size = asize.v
        self.var_map[asize.v] = asize
        self.type = atype
        self.args = []
        for arg in args:
            self.var_map[arg.v] = arg
            self.args.append(arg.v)

    def is_propagable(self):
        return False

    def has_side_effect(self):
        return True

    def get_used_vars(self):
        lused_vars = []
        for arg in self.args:
            lused_vars.extend(self.var_map[arg].get_used_vars())
        lused_vars.append(self.size)
        return list(set(lused_vars))

    def visit(self, visitor):
        v_m = self.var_map
        largs = [v_m[arg] for arg in self.args]
        return visitor.visit_filled_new_array(self.type, v_m[self.size], largs)


class FillArrayExpression(ArrayExpression):
    def __init__(self, reg, value):
        super(FillArrayExpression, self).__init__()
        self.reg = reg.v
        self.var_map[reg.v] = reg
        self.value = value

    def is_propagable(self):
        return False

    def get_rhs(self):
        return self.reg

    def get_used_vars(self):
        return self.var_map[self.reg].get_used_vars()

    def visit(self, visitor):
        return visitor.visit_fill_array(self.var_map[self.reg], self.value)


class RefExpression(IRForm):
    def __init__(self, ref):
        super(RefExpression, self).__init__()
        self.ref = ref.v
        self.var_map[ref.v] = ref

    def get_used_vars(self):
        return self.var_map[self.ref].get_used_vars()

    def modify_rhs(self, old, new):
        if old in self.var_map:
            self.var_map[old] = new
        else:
            self.var_map[self.ref].modify_rhs(old, new)


class MonitorEnterExpression(RefExpression):
    def __init__(self, ref):
        super(MonitorEnterExpression, self).__init__(ref)

    def visit(self, visitor):
        return visitor.visit_monitor_enter(self.var_map[self.ref])


class MonitorExitExpression(RefExpression):
    def __init__(self, ref):
        super(MonitorExitExpression, self).__init__(ref)

    def visit(self, visitor):
        return visitor.visit_monitor_exit(self.var_map[self.ref])


class ThrowExpression(RefExpression):
    def __init__(self, ref):
        super(ThrowExpression, self).__init__(ref)

    def visit(self, visitor):
        return visitor.visit_throw(self.var_map[self.ref])


class BinaryExpression(IRForm):
    def __init__(self, op, arg1, arg2, type):
        super(BinaryExpression, self).__init__()
        self.op = op
        self.arg1 = arg1.v
        self.arg2 = arg2.v
        self.var_map.update([(arg1.v, arg1), (arg2.v, arg2)])
        self.type = type

    # TODO: return the max type of arg1 & arg2
    def get_type(self):
        return None

    def has_side_effect(self):
        v_m = self.var_map
        return (v_m[self.arg1].has_side_effect() or
                v_m[self.arg2].has_side_effect())

    def get_used_vars(self):
        v_m = self.var_map
        lused_vars = v_m[self.arg1].get_used_vars()
        lused_vars.extend(v_m[self.arg2].get_used_vars())
        return list(set(lused_vars))

    def visit(self, visitor):
        v_m = self.var_map
        return visitor.visit_binary_expression(self.op, v_m[self.arg1],
                                                        v_m[self.arg2])

    def modify_rhs(self, old, new):
        if old in self.var_map:
            self.var_map[old] = new
        else:
            arg1 = self.var_map[self.arg1]
            arg2 = self.var_map[self.arg2]
            for arg in (arg1, arg2):
                if not (arg.is_ident() or arg.is_const()):
                    arg.modify_rhs(old, new)

    def __str__(self):
        v_m = self.var_map
        return '(%s %s %s)' % (self.op, v_m[self.arg1], v_m[self.arg2])


class BinaryCompExpression(BinaryExpression):
    def __init__(self, op, arg1, arg2, type):
        super(BinaryCompExpression, self).__init__(op, arg1, arg2, type)

    def visit(self, visitor):
        v_m = self.var_map
        return visitor.visit_cond_expression(self.op, v_m[self.arg1],
                                                      v_m[self.arg2])


class BinaryExpression2Addr(BinaryExpression):
    def __init__(self, op, dest, arg, type):
        super(BinaryExpression2Addr, self).__init__(op, dest, arg, type)


class BinaryExpressionLit(BinaryExpression):
    def __init__(self, op, arg1, arg2):
        super(BinaryExpressionLit, self).__init__(op, arg1, arg2, 'I')


class UnaryExpression(IRForm):
    def __init__(self, op, arg):
        super(UnaryExpression, self).__init__()
        self.op = op
        self.arg = arg.v
        self.var_map[arg.v] = arg

    def get_type(self):
        return self.var_map[self.arg].get_type()

    def get_used_vars(self):
        return self.var_map[self.arg].get_used_vars()

    def visit(self, visitor):
        return visitor.visit_unary_expression(self.op, self.var_map[self.arg])

    def modify_rhs(self, old, new):
        if old in self.var_map:
            self.var_map[old] = new
        else:
            arg = self.var_map[self.arg]
            if not (arg.is_const() or arg.is_ident()):
                arg.modify_rhs(old, new)

    def __str__(self):
        return '(%s, %s)' % (self.op, self.var_map[self.arg])


class CastExpression(UnaryExpression):
    def __init__(self, op, atype, arg):
        super(CastExpression, self).__init__(op, arg)
        self.type = atype

    def get_type(self):
        return self.type

    def get_used_vars(self):
        return self.var_map[self.arg].get_used_vars()

    def visit(self, visitor):
        return visitor.visit_cast(self.op, self.var_map[self.arg])

    def __str__(self):
        return 'CAST_%s(%s)' % (self.op, self.arg)


CONDS = {
    '==': '!=',
    '!=': '==',
    '<': '>=',
    '<=': '>',
    '>=': '<',
    '>': '<=',
}


class ConditionalExpression(IRForm):
    def __init__(self, op, arg1, arg2):
        super(ConditionalExpression, self).__init__()
        self.op = op
        self.arg1 = arg1.v
        self.arg2 = arg2.v
        self.var_map.update([(arg1.v, arg1), (arg2.v, arg2)])

    def get_lhs(self):
        return None

    def is_cond(self):
        return True

    def get_used_vars(self):
        v_m = self.var_map
        lused_vars = v_m[self.arg1].get_used_vars()
        lused_vars.extend(v_m[self.arg2].get_used_vars())
        return list(set(lused_vars))

    def neg(self):
        self.op = CONDS[self.op]

    def visit(self, visitor):
        v_m = self.var_map
        return visitor.visit_cond_expression(self.op, v_m[self.arg1],
                                                      v_m[self.arg2])

    def modify_rhs(self, old, new):
        if old in self.var_map:
            self.var_map[old] = new
        else:
            arg1 = self.var_map[self.arg1]
            arg2 = self.var_map[self.arg2]
            for arg in (arg1, arg2):
                if not (arg.is_ident() or arg.is_const()):
                    arg.modify_rhs(old, new)

    def __str__(self):
        v_m = self.var_map
        return 'COND(%s, %s, %s)' % (self.op, v_m[self.arg1], v_m[self.arg2])


class ConditionalZExpression(IRForm):
    def __init__(self, op, arg):
        super(ConditionalZExpression, self).__init__()
        self.op = op
        self.arg = arg.v
        self.var_map[arg.v] = arg

    def get_lhs(self):
        return None

    def is_cond(self):
        return True

    def get_used_vars(self):
        return self.var_map[self.arg].get_used_vars()

    def neg(self):
        self.op = CONDS[self.op]

    def visit(self, visitor):
        return visitor.visit_condz_expression(self.op, self.var_map[self.arg])

    def modify_rhs(self, old, new):
        if old in self.var_map:
            self.var_map[old] = new
        else:
            arg = self.var_map[self.arg]
            if not (arg.is_ident() or arg.is_const()):
                arg.modify_rhs(old, new)

    def __str__(self):
        return '(IS%s0, %s)' % (self.op, self.var_map[self.arg])


class InstanceExpression(IRForm):
    def __init__(self, arg, klass, ftype, name):
        super(InstanceExpression, self).__init__()
        self.arg = arg.v
        self.cls = klass
        self.ftype = ftype
        self.name = name
        self.var_map[arg.v] = arg

    def get_type(self):
        return self.ftype

    def get_used_vars(self):
        return self.var_map[self.arg].get_used_vars()

    def visit(self, visitor):
        return visitor.visit_get_instance(self.var_map[self.arg], self.name)

    def modify_rhs(self, old, new):
        if old in self.var_map:
            self.var_map[old] = new
        else:
            arg = self.var_map[self.arg]
            if not (arg.is_ident() or arg.is_const()):
                arg.modify_rhs(old, new)

    def __str__(self):
        return '%s.%s' % (self.var_map[self.arg], self.name)


class StaticExpression(IRForm):
    def __init__(self, cls_name, field_type, field_name):
        super(StaticExpression, self).__init__()
        self.cls = cls_name
        self.ftype = field_type
        self.name = field_name

    def get_type(self):
        return self.ftype

    def visit(self, visitor):
        return visitor.visit_get_static(self.cls, self.name)

    def modify_rhs(self, old, new):
        pass

    def __str__(self):
        return '%s.%s' % (self.cls, self.name)
