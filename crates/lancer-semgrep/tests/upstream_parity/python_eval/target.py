def go():
    user_input = read_line()
    # ruleid: python.dangerous-eval
    eval(user_input)
