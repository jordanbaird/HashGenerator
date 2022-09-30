generate_docs:
	swift package --allow-writing-to-directory docs \
		generate-documentation --target HashGenerator \
		--disable-indexing \
		--transform-for-static-hosting \
		--hosting-base-path HashGenerator \
		--output-path docs
