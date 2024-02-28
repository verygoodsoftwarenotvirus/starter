#!/usr/bin/env bash

directory=$1

mkdir -p "${directory}_cloud_function"
cp "cmd/functions/$directory/function.go" "${directory}_cloud_function/function.go"
sed "s/replace\sgithub\.com\/verygoodsoftwarenotvirus\/starter\s=>\s\.\.\/\.\.\/\.\.\//replace github\.com\/verygoodsoftwarenotvirus\/starter => \.\.\//" cmd/functions/${directory}/go.mod > ${directory}_cloud_function/go.mod
(cd "${directory}_cloud_function" && go mod tidy && go mod vendor)
mv "${directory}_cloud_function" environments/dev/terraform
