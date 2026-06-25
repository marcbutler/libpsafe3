#pragma once
// https://github.com/marcbutler/libpsafe3/LICENSE

namespace psafe3 {

template <typename T, auto F>
struct Handle {
    bool holding = false;
    T actual;
    void acquire()
    {
        holding = true;
    }
    void release()
    {
        holding = false;
        actual = T();
    }
    T operator()()
    {
        return actual;
    }
    ~Handle()
    {
        F(actual);
    }
};

} // namespace psafe3
