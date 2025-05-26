// src/binding.cpp
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "softtpm.hpp"

namespace py = pybind11;

PYBIND11_MODULE(softtpm_py, m) {
    m.doc() = "SoftTPM Python binding";

    py::class_<SoftTPM>(m, "SoftTPM")
        .def(py::init<const std::string&>(), py::arg("path") = ".softtpm")
        .def("extend_pcr", &SoftTPM::extendPCR, py::arg("index"), py::arg("data"))
        .def("quote", &SoftTPM::quote, py::arg("nonce"), py::arg("mask"))
        .def("get_random", &SoftTPM::getRandom, py::arg("n"))
        .def("hmac", &SoftTPM::hmac, py::arg("key"), py::arg("data"))
        .def("sha256", &SoftTPM::sha256, py::arg("data"))
        .def("aes_encrypt", &SoftTPM::aesEncrypt, py::arg("key"), py::arg("iv"), py::arg("data"))
        .def("aes_decrypt", &SoftTPM::aesDecrypt, py::arg("key"), py::arg("iv"), py::arg("data"))
        .def("ecdh", &SoftTPM::ecdh, py::arg("peer_pub"))
        .def("nv_write", &SoftTPM::nvWrite, py::arg("index"), py::arg("data"))
        .def("nv_read", &SoftTPM::nvRead, py::arg("index"))
        .def("inc_counter", &SoftTPM::incCounter);
}
