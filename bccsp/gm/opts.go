/*
Copyright 2023 kasdect@163.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gm

const (
	SM2 = "SM2"
	SM4 = "SM4"
)

type SM2KeyGenOpts struct {
	Temporary bool
}

func (opts *SM2KeyGenOpts) Algorithm() string {
	return SM2
}

func (opts *SM2KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM4KeyGenOpts struct {
	Temporary bool
}

func (opts *SM4KeyGenOpts) Algorithm() string {
	return SM4
}

func (opts *SM4KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM4ImportKeyOpts struct {
	Temporary bool
}

func (opts *SM4ImportKeyOpts) Algorithm() string {
	return SM4
}

func (opts *SM4ImportKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM2PrivateKeyImportOpts struct {
	Temporary bool
}

func (opts *SM2PrivateKeyImportOpts) Algorithm() string {
	return SM2
}

func (opts *SM2PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM2PublicKeyImportOpts struct {
	Temporary bool
}

func (opts *SM2PublicKeyImportOpts) Algorithm() string {
	return SM2
}

func (opts *SM2PublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM2PublicKeyDerivOpts struct {
	Temporary bool
}

func (opts *SM2PublicKeyDerivOpts) Algorithm() string {
	return SM2
}

func (opts *SM2PublicKeyDerivOpts) Ephemeral() bool {
	return opts.Temporary
}

type HashOpts struct{}

// Algorithm implements bccsp.HashOpts.
func (*HashOpts) Algorithm() string {
	panic("unimplemented")
}
