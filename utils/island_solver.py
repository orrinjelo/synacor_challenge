grid = [['*', 8, '-',  1 ],
        [ 4, '*', 11, '*'],
        ['+', 4, '-',  18],
        [ 22,'-', 9,  '*']
       ]

x, y = 0, 3

def calculate(l):
    res = l[0]
    op = None
    for i in range(len(l)):
        if type(l[i]) is str and l[i] in '*-+':
            op = l[i]
        else:
            if op == None:
                res = l[0]
            elif op == '+':
                res += l[i]
            elif op == '-':
                res -= l[i]
            elif op == '*':
                res *= l[i]
    return res

assert(calculate([3, '*', 3]) == 9)
assert(calculate([3, '+', 3]) == 6)
assert(calculate([3, '-', 3]) == 0)
assert(calculate([3, '*', 3, '+', 3, '-', 1, '*', 5]) == 55)


def run_path(grid, x=0, y=3, history=None, path=None, rec=(0,8)):
    if history is None:
        history = [grid[y][x]]
        path = [(x,y)]
    else:
        history.append(grid[y][x])
        path.append((x,y))
    if calculate(history) == 30 and x == 3 and y == 0:
        print(history, path)
        return history, path
    elif rec[0] == rec[1]:
        return None
    # try:
    if x > 0:
        res = run_path(grid, x-1, y, history, path, (rec[0]+1,rec[1]))
        if res is not None:
            return res
    if y > 0:
        res = run_path(grid, x, y-1, history, path, (rec[0]+1,rec[1]))
        if res is not None:
            return res
    if x < 3:
        res = run_path(grid, x+1, y, history, path, (rec[0]+1,rec[1]))
        if res is not None:
            return res
    if y < 3:
        res = run_path(grid, x, y+1, history, path, (rec[0]+1,rec[1]))
        if res is not None:
            return res
    # except Exception as e:
    #     print(e)
    #     return None
    return None

run_path(grid)