#![feature(proc_macro_diagnostic)]

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    spanned::Spanned,
    Expr, Ident, Token,
};

struct SyscallMacroInfo {
    name: Ident,
    args: Vec<(Ident, Expr)>,
    tags: Punctuated<Ident, Token![,]>,
}

impl Parse for SyscallMacroInfo {
    fn parse(input: ParseStream) -> syn::parse::Result<Self> {
        let name: Ident = input.parse()?;
        let mut args: Vec<(Ident, Expr)> = Vec::new();
        while input.parse::<Token![,]>().is_ok() {
            let arg_name: Ident = if let Ok(arg_name) = input.parse() {
                arg_name
            } else {
                Ident::new("type", input.parse::<Token![type]>()?.span())
            };
            input.parse::<Token![=]>()?;
            let arg_ty: Expr = input.parse()?;
            args.push((arg_name, arg_ty));
        }

        let tags = if input.parse::<Token![;]>().is_ok() {
            Punctuated::parse_terminated(input)?
        } else {
            Punctuated::new()
        };

        Ok(SyscallMacroInfo { name, args, tags })
    }
}

#[proc_macro]
pub fn syscall(input: TokenStream) -> TokenStream {
    let SyscallMacroInfo { name, args, tags } = parse_macro_input!(input as SyscallMacroInfo);

    if args.len() > 6 {
        args[6].0.span().unwrap().error("too many arguments").emit();
        return TokenStream::new();
    }
    let mut arg_names = args
        .iter()
        .map(|it| &it.0)
        .map(|it| quote! { stringify!(#it) })
        .collect::<Vec<_>>();
    while arg_names.len() < 6 {
        arg_names.push(quote! { "" });
    }
    let mut real_args = args
        .iter()
        .map(|it| &it.1)
        .map(|it| quote! { #it })
        .collect::<Vec<_>>();
    while real_args.len() < 6 {
        real_args.push(quote! { (ArgType::empty(), 0, &self::formatter::VOID_ARG_FORMATTER) });
    }
    let tags = tags
        .iter()
        .map(|it| {
            quote! {
                let tags = tags.union(crate::filter::Tags::#it);
            }
        })
        .collect::<Vec<_>>();

    let expanded = quote! {
        pub const #name: SyscallInfo = SyscallInfo {
            arg_names: [#(#arg_names),*],
            args: [#(#real_args),*],
            tags: {
                let tags = crate::filter::Tags::empty();
                #(#tags)*
                tags
            },
        };
    };

    TokenStream::from(expanded)
}
