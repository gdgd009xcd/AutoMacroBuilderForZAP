package org.zaproxy.zap.extension.automacrobuilder.zap;

import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;

/**
 * Collector&lt;T:the type of input, A:the Class of Accumrator, R: the type of Result&gt;
 * tips: lambda is functional interface's instance object. only one method can provides in interface.
 *
 */
public class BaseStringCollector implements Collector<String,StringBuilder,String> {

    /**
     * supplier : ｐrovides accumlator class instance for collecting inputs.
     * @return labmda function
     */
    @Override
    public Supplier<StringBuilder> supplier() {

        // below code return lambda function with no arguments.
        // this is the same as : return () -> {return new StringBuilder();};
        // StringBuilder::new is method reference.
        // from Java 8, this syntax automatically convert lambda with returning specified method reference.
        return StringBuilder::new;

    }

    /**
     * accumlator: collect input data and store it into accumlator
     * this lambda function has two arguments and has no return value.
     * @return labmda function
     */
    @Override
    public BiConsumer<StringBuilder, String> accumulator() {
        return (builder, string) -> {
            builder.append(string);
        };
    }

    /**
     * combiner: In parallel stream, this combines two accumlator objects into one object.
     * if you do not use parallel stream, this function is no effect.
     * @return lambda function
     */
    @Override
    public BinaryOperator<StringBuilder> combiner() {
        return (builderA, builderB) -> {
            builderA.append(builderB);
            return builderA;
        };
    }

    /**
     * finisher: returns String as result of all combined accumulator objects.
     * @return lambda function
     */
    @Override
    public Function<StringBuilder, String> finisher() {
        return builder -> builder.toString();
    }

    @Override
    public Set<Characteristics> characteristics() {
        return Set.of();
    }
}
