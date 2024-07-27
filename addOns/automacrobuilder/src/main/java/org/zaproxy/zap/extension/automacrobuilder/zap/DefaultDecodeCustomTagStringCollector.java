package org.zaproxy.zap.extension.automacrobuilder.zap;

import java.util.function.BiConsumer;
import java.util.function.Function;

public class DefaultDecodeCustomTagStringCollector extends BaseStringCollector {

    private final StringBuilder partBuilder = new StringBuilder();
    private static final CustomTagConverter converter = CustomTagConverter.getCustomStringConverter();

    /**
     * accumlator: collect input data and store it into accumlator
     * this lambda function has two arguments and has no return value.
     * @return labmda function
     */
    @Override
    public BiConsumer<StringBuilder, String> accumulator() {

        return (builder, string) -> {
            partBuilder.append(string);
            if (converter.maxEncodedLength == partBuilder.length()) {
                Character c = converter.convEncoded2Original.get(partBuilder.toString());
                if (c != null) {
                    builder.append(c);
                    partBuilder.delete(0, partBuilder.length());
                } else {
                    builder.append(partBuilder.toString().substring(0, 1));
                    partBuilder.delete(0, 1);
                }
            }
        };
    }

    /**
     * finisher: returns String as result of all combined accumulator objects.
     * @return
     */
    @Override
    public Function<StringBuilder, String> finisher() {
        return (builder) -> {
            builder.append(partBuilder);
            return builder.toString();
        };
    }
}
